import { ethers } from 'hardhat'
import { BigNumber } from 'ethers'
import { parseEther } from 'ethers/lib/utils'
import {
  ERC1967Proxy__factory,
  FalconSimpleAccount__factory,
  EntryPoint__factory,
} from '../typechain'

import { fillUserOpDefaults, getUserOpHash, packUserOp } from '../test/UserOp'

const { getKernel } = require('falcon-sign')

// Unpack utilities
function decodePk(inData: Uint8Array): BigInt[] {
  const n = 512;
  const x: BigInt[] = [];
  let acc = 0, accLen = 0, bufIdx = 1;
  for (let u = 0; u < n; u++) {
    while (accLen < 14) {
      acc = (acc << 8) | inData[bufIdx++];
      accLen += 8;
    }
    accLen -= 14;
    x.push(BigInt((acc >> accLen) & 0x3FFF));
  }
  return x;
}

function decompressS2(signMsg: Uint8Array): { s2: BigInt[], salt: Uint8Array } {
  const salt = signMsg.subarray(2, 42);
  const state = { acc: 0, accLen: 0, bufIdx: 43 };

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

  const s2: BigInt[] = [];
  const q = BigInt(12289);
  for (let u = 0; u < 512; u++) {
    let b = readBits(8);
    let s = b & 128, m = b & 127;
    while (readBit() === 0) m += 128;
    let valBig = BigInt(s ? -m : m);
    if (valBig < BigInt(0)) valBig += q;
    s2.push(valBig);
  }
  return { s2, salt };
}

async function main() {
  console.log("Starting Falcon PQ-Signed Transfer on Anvil Node...");

  const accounts = await ethers.getSigners()
  const ethersSigner = accounts[0]
  const receiver = accounts[2].address
  console.log("-> Using Bundler/Funder EOA:", ethersSigner.address)

  // 1. Deploy EntryPoint
  process.stdout.write("-> Deploying EntryPoint... ")
  const entryPoint = await new EntryPoint__factory(ethersSigner).deploy()
  console.log(entryPoint.address)

  // 2. Deploy Falcon Verifier Stack
  process.stdout.write("-> Deploying Falcon PQ Verification Stack... ")
  const FalconConstantsFactory = await ethers.getContractFactory("FalconConstants");
  const falconConstants = await FalconConstantsFactory.deploy();

  const H2PFactory = await ethers.getContractFactory("ZKNOX_HashToPoint");
  const h2p = await H2PFactory.deploy();

  const NTTFactory = await ethers.getContractFactory("ZKNOX_NTT");
  const ntt = await NTTFactory.deploy(falconConstants.address, falconConstants.address, 12289, 12265);

  const FalconFactory = await ethers.getContractFactory("ZKNOX_falcon");
  const falconVerifier = await FalconFactory.deploy(ntt.address, h2p.address);
  console.log(`Ready (Verifier: ${falconVerifier.address})`)

  // 3. Generate Falcon Keypair
  process.stdout.write("-> Generating Post-Quantum Falcon-512 Keypair... ")
  const Falcon512 = await getKernel('falcon512_n3_v1')
  const keypair = Falcon512.genkey()
  const publicKey = decodePk(keypair.pk)
  console.log("Ready")

  // 4. Deploy FalconSmartAccount
  process.stdout.write("-> Proxifying and deploying Falcon Smart Account... ")
  const implementation = await new FalconSimpleAccount__factory(ethersSigner).deploy(entryPoint.address)
  const proxy = await new ERC1967Proxy__factory(ethersSigner).deploy(implementation.address, '0x')
  const account = FalconSimpleAccount__factory.connect(proxy.address, ethersSigner)
  await account.initialize(ethersSigner.address, Array.from(publicKey), falconVerifier.address)
  
  const pk0 = await account.publicKey(0)
  console.log("Account Proxy PublicKey[0]:", pk0.toString())
  
  console.log(account.address)

  // 5. Fund Account & EntryPoint Deposit
  process.stdout.write("-> Funding Account and Adding Gas Deposit... ")
  await ethersSigner.sendTransaction({ to: account.address, value: parseEther('10.0') })
  await account.addDeposit({ value: parseEther('1.0') })
  console.log("Funded")

  // 6. Forge UserOp
  console.log("\n[Forging Transaction]")
  console.log(`Action: Transfer 0.1 ETH from Falcon Wallet ${account.address} --> ${receiver}`)
  const callData = account.interface.encodeFunctionData('execute', [receiver, parseEther('0.1'), '0x'])
  
  const callGasLimit = 300000
  const verificationGasLimit = 100000000 // 100m gas
  const maxFeePerGas = 3e9
  const chainId = await ethers.provider.getNetwork().then(net => net.chainId)

  const op = fillUserOpDefaults({
    sender: account.address,
    callData,
    callGasLimit,
    verificationGasLimit,
    maxFeePerGas
  })

  // 6. Sign it via Falcon kernel
  console.log(`-> Deriving userOpHash via EntryPoint directly...`)
  const userOpHash = await entryPoint.getUserOpHash(packUserOp(op))
  console.log(userOpHash)

  process.stdout.write("-> Signing hashing via Falcon512 C-WASM module... ")
  const payloadToSign = ethers.utils.arrayify(userOpHash)
  const signMsg = Falcon512.sign(payloadToSign, keypair.sk)
  console.log("Signed")

  process.stdout.write("-> Decompressing signature and ABI compiling... ")
  const { s2, salt } = decompressS2(signMsg)
  const saltHex = '0x' + Buffer.from(salt).toString('hex')
  const encodedSignature = ethers.utils.defaultAbiCoder.encode(["uint256[512]", "bytes"], [s2, saltHex])
  console.log("Compiled")

  const userOp = { ...op, signature: encodedSignature }
  const packedOp = packUserOp(userOp)

  // 8. Submit transaction through handleOps
  console.log(`\n-> Relaying to EntryPoint Mempool using Bundler (${ethersSigner.address})...`)
  try {
    await entryPoint.connect(ethersSigner).callStatic.handleOps([packedOp], ethersSigner.address, {
      gasLimit: BigNumber.from("150000000") // Give it huge gas due to NTT verifier math
    })
  } catch (e: any) {
    console.error("SIMULATION REVERTED:");
    console.error(e.errorName ? `Name: ${e.errorName}` : e.message);
    if (e.errorArgs) console.error("Args:", e.errorArgs);
    throw e;
  }

  const tx = await entryPoint.connect(ethersSigner).handleOps([packedOp], ethersSigner.address, {
    gasLimit: BigNumber.from("150000000")
  })
  
  console.log(`-> Waiting for Anvil Confirmation... (tx hash: ${tx.hash})`)
  const receipt = await tx.wait()
  
  console.log("\n==================================")
  console.log("SUCCESS!")
  console.log(`Transaction Hash: ${receipt.transactionHash}`)
  console.log(`Gas Used: ${receipt.gasUsed.toString()}`)
  console.log("PQ Verified and Native ETH execution confirmed!")
  console.log("==================================\n")
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
