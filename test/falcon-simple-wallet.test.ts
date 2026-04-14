import { Wallet, BigNumber } from 'ethers'
import { ethers } from 'hardhat'
import { expect } from 'chai'
import { bufferToHex } from 'ethereumjs-util'


import {
  ERC1967Proxy__factory,
  EntryPoint,
  FalconSimpleAccount,
  FalconSimpleAccount__factory,
  TestUtil,
  TestUtil__factory
} from '../typechain'
import {
  createAccountOwner,
  deployEntryPoint,
  getBalance,
 
} from './testutils'
import { fillUserOpDefaults, getUserOpHash, encodeUserOp, packUserOp } from './UserOp'
import { parseEther } from 'ethers/lib/utils'
import { UserOperation } from './UserOperation'
const { getKernel,util } = require('falcon-sign');

// Helpers for Falcon Decompression
// Decodes public key elements (14-bit packed) into 512 coefficients
function decodePk(inData: Uint8Array): BigInt[] {
  const n = 512;
  const x: BigInt[] = [];
  let acc = 0;
  let accLen = 0;
  let bufIdx = 1; // start after header byte
  for (let u = 0; u < n; u++) {
    while (accLen < 14) {
      acc = (acc << 8) | inData[bufIdx++];
      accLen += 8;
    }
    accLen -= 14;
    const w = (acc >> accLen) & 0x3FFF;
    x.push(BigInt(w));
  }
  return x;
}

// Unpacks signature salt and polynomial coefficients
function decompressS2(signMsg: Uint8Array): { s2: BigInt[], salt: Uint8Array } {
  const salt = signMsg.subarray(2, 42); // 40 bytes nonce
  const state = { acc: 0, accLen: 0, bufIdx: 43 }; // 43 is after header 0x29

  function readBits(bits: number): number {
    while (state.accLen < bits) {
      state.acc = (state.acc << 8) | signMsg[state.bufIdx++];
      state.accLen += 8;
    }
    state.accLen -= bits;
    return (state.acc >> state.accLen) & ((1 << bits) - 1);
  }

  function readBit(): number {
    if (state.accLen === 0) {
      state.acc = (state.acc << 8) | signMsg[state.bufIdx++];
      state.accLen = 8;
    }
    state.accLen--;
    return (state.acc >> state.accLen) & 1;
  }

  const n = 512;
  const s2: BigInt[] = [];
  const q = BigInt(12289);

  for (let u = 0; u < n; u++) {
    let b = readBits(8);
    let s = b & 128;
    let m = b & 127;
    while (true) {
      if (readBit() !== 0) {
        break;
      }
      m += 128;
    }
    let valBig = BigInt(s ? -m : m);
    if (valBig < BigInt(0)) {
      valBig = valBig + q;
    }
    s2.push(valBig);
  }
  return { s2, salt };
}

describe('FalconSimpleAccount', function () {
  let entryPoint: EntryPoint
  let accounts: string[]
  let testUtil: TestUtil
  let accountOwner: Wallet
  const ethersSigner = ethers.provider.getSigner()

  before(async function () {
    entryPoint = await deployEntryPoint()
    accounts = await ethers.provider.listAccounts()
    // ignore in geth.. this is just a sanity test. should be refactored to use a single-account mode..
    if (accounts.length < 2) this.skip()
    testUtil = await new TestUtil__factory(ethersSigner).deploy()
    accountOwner = createAccountOwner()
  })

  describe('#validateUserOp', () => {
    let account: FalconSimpleAccount
    let userOp: UserOperation
    let userOpHash: string
    let preBalance: number
    let expectedPay: number

    const actualGasPrice = 1e9
    // for testing directly validateUserOp, we initialize the account with EOA as entryPoint.
    let entryPointEoa: string

    before(async () => {
      // Wait for the Falcon512 kernel
      let Falcon512 = await getKernel('falcon512_n3_v1'); // Get falcon512_n3_v1 Kernel
      let keypair = Falcon512.genkey(); // { sk, pk, genKeySeed }

      /* 
      * We unpack the 14-bit packed array to recover the 512 uint256 coefficients
      * required for the smart contract verifier.
      */
      const publicKey = decodePk(keypair.pk)
      entryPointEoa = accounts[2]
      const epAsSigner = await ethers.getSigner(entryPointEoa)

      // Pre-deploy the Falcon verifier stack separately to stay under the 24KB contract size limit
      const FalconConstantsFactory = await ethers.getContractFactory("FalconConstants");
      const falconConstants = await FalconConstantsFactory.deploy();

      const H2PFactory = await ethers.getContractFactory("ZKNOX_HashToPoint");
      const h2p = await H2PFactory.deploy();

      const NTTFactory = await ethers.getContractFactory("ZKNOX_NTT", {
        libraries: {}
      });
      const ntt = await NTTFactory.deploy(falconConstants.address, falconConstants.address, 12289, 12265);

      const FalconFactory = await ethers.getContractFactory("ZKNOX_falcon");
      const falconVerifier = await FalconFactory.deploy(ntt.address, h2p.address);

      // cant use "SimpleAccountFactory", since it attempts to increment nonce first
      const implementation = await new FalconSimpleAccount__factory(ethersSigner).deploy(entryPointEoa)
      const proxy = await new ERC1967Proxy__factory(ethersSigner).deploy(implementation.address, '0x')
      account = FalconSimpleAccount__factory.connect(proxy.address, epAsSigner)
      await account.initialize(accountOwner.address, Array.from(publicKey), falconVerifier.address)

      await ethersSigner.sendTransaction({ from: accounts[0], to: account.address, value: parseEther('0.2') })
      const callGasLimit = 200000
      const verificationGasLimit = 100000
      const maxFeePerGas = 3e9
      const chainId = await ethers.provider.getNetwork().then(net => net.chainId)
   
      let op = fillUserOpDefaults({
        sender: account.address,
        callGasLimit,
        verificationGasLimit,
        maxFeePerGas
      })
      userOpHash = await getUserOpHash(op, entryPointEoa, chainId)

      // Sign the UserOpHash with Falcon512 natively!
      const payloadToSign = ethers.utils.arrayify(userOpHash);
      
      // Let Falcon512 generate its own random 40-byte salt and sign
      let signMsg = Falcon512.sign(payloadToSign, keypair.sk);
      
      // Decompress the signature into coefficients and extract the generated salt
      const { s2, salt } = decompressS2(signMsg);

      // Encode s2 coefficients + salt into userOp.signature via ABI encoding
      const saltHex = '0x' + Buffer.from(salt).toString('hex')
      const encodedSignature = ethers.utils.defaultAbiCoder.encode(
        ["uint256[512]", "bytes"],
        [s2, saltHex]
      );

      userOp = {
        ...op,
        signature: encodedSignature
      }
      expectedPay = actualGasPrice * (callGasLimit + verificationGasLimit)
      preBalance = await getBalance(account.address)
      console.log(`JS s2[0]: ${s2[0].toString()}`);
      console.log(`JS publicKey[0]: ${publicKey[0].toString()}`);

      const packedOp = packUserOp(userOp)
      const ret = await account.callStatic.validateUserOp(packedOp, userOpHash, expectedPay, { gasPrice: actualGasPrice, gasLimit: BigNumber.from(30000000) })
      expect(ret).to.equal(0);
      
      const tx = await account.validateUserOp(packedOp, userOpHash, expectedPay, { gasPrice: actualGasPrice, gasLimit: BigNumber.from(30000000) })
      await tx.wait()
    })

    it('should pay', async () => {
      const postBalance = await getBalance(account.address)
      expect(preBalance - postBalance).to.eql(expectedPay)
    })

    /*it('should return NO_SIG_VALIDATION on wrong signature', async () => {
      const userOpHash = HashZero
      const packedOp = packUserOp(userOp)
      const deadline = await account.callStatic.validateUserOp({ ...packedOp, nonce: 1 }, userOpHash, 0)
      expect(deadline).to.eq(1)
    })*/

  })
})
