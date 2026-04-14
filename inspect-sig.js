const { getKernel, util } = require('falcon-sign');

(async () => {
  const Falcon512 = await getKernel('falcon512_n3_v1');
  const keypair = Falcon512.genkey();

  console.log('=== SIZES ===');
  console.log('pk bytes:', keypair.pk.length);
  console.log('sk bytes:', keypair.sk.length);
  console.log('signSaltByte:', Falcon512.signSaltByte);
  console.log('signNonceByte:', Falcon512.signNonceByte);
  console.log('signByte (max):', Falcon512.signByte);

  const salt = util.hexStringToUint8Array('f41f1009826c203576ce1e1ed3f27622c0e1cd1a');
  console.log('\nsalt bytes:', salt.length);

  const msg = 'test message';
  const signMsg = Falcon512.sign(msg, keypair.sk, salt);
  console.log('\n=== SIGNATURE OUTPUT ===');
  console.log('signMsg total bytes:', signMsg.length);
  console.log('first 4 bytes (hex):', util.uint8ArrayToString(signMsg.subarray(0, 4)));
  
  // Falcon signature format: [2-byte length][nonce][compressed s2]
  const sigLen = new DataView(signMsg.buffer).getUint16(0);
  console.log('encoded sig length field:', sigLen);
  console.log('nonce bytes:', Falcon512.signNonceByte);
  console.log('nonce:', util.uint8ArrayToString(signMsg.subarray(2, 2 + Falcon512.signNonceByte)));
  console.log('compressed sig bytes:', signMsg.length - 2 - Falcon512.signNonceByte);
  
  // The Solidity verifier wants:
  // - s2: 512 uint256 values (polynomial coefficients mod q=12289)
  // - salt: 40 bytes
  // The JS sign output is COMPRESSED Falcon format, not raw polynomial coefficients
  
  // Check if Array.from gives us the raw bytes
  const signArray = Array.from(signMsg);
  console.log('\n=== As Array ===');
  console.log('array length:', signArray.length);
  console.log('first 10 values:', signArray.slice(0, 10));
  console.log('max value:', Math.max(...signArray));
  
  // The hardcoded s2 values are in range [0, 12289] - these are polynomial coefficients
  // Array.from(signMsg) gives bytes [0, 255] - these are compressed bytes
  // We need to DECOMPRESS the signature to get polynomial coefficients
  
  console.log('\n=== PUBLIC KEY ===');
  console.log('pk first 20 bytes:', Array.from(keypair.pk.subarray(0, 20)));
  
  // pk is encoded as bytes, needs to be decoded to 512 coefficients mod q  
  // Falcon-512 pk format: 1 header byte + 512 * 14-bit coefficients
  const pkHeader = keypair.pk[0];
  console.log('pk header byte:', pkHeader.toString(16));

  // Verify roundtrip
  console.log('\n=== VERIFY ===');
  console.log('verify result:', Falcon512.verify(signMsg, msg, keypair.pk));
})();
