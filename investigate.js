const { getKernel, util } = require('falcon-sign');

(async () => {
  const Falcon512 = await getKernel('falcon512_n3_v1');
  
  // Check all exported WASM functions
  const kernel = require('../falcon-sign-js/kernel/n3_v1/wasmFile/falcon512.js');
  await new Promise(res => {
    if (kernel.calledRun) return res();
    kernel.onRuntimeInitialized = res;
  });
  
  console.log('=== WASM EXPORTS ===');
  const exports = Object.keys(kernel).filter(k => k.startsWith('_') && typeof kernel[k] === 'function');
  console.log(exports.join('\n'));
  
  console.log('\n=== KEY SIZES ===');
  console.log('getPkByte:', kernel._getPkByte());
  console.log('getSkByte:', kernel._getSkByte()); 
  console.log('getCryptoByte:', kernel._getCryptoByte());
  console.log('getCryptoSaltByte:', kernel._getCryptoSaltByte());
  console.log('getCryptoNonceByte:', kernel._getCryptoNonceByte());
  console.log('getGenKeySeedByte:', kernel._getGenKeySeedByte());
  
  // Generate a keypair and sign
  const keypair = Falcon512.genkey();
  const salt20 = util.hexStringToUint8Array('f41f1009826c203576ce1e1ed3f27622c0e1cd1a');
  const msg = 'test';
  const signMsg = Falcon512.sign(msg, keypair.sk, salt20);
  
  console.log('\n=== SIGNATURE STRUCTURE ===');
  console.log('Total bytes:', signMsg.length);
  
  // Parse the structure
  const sigLen = (signMsg[0] << 8) | signMsg[1]; // big-endian uint16
  console.log('Sig length field (big-endian):', sigLen);
  
  const sigLenLE = signMsg[0] | (signMsg[1] << 8); // little-endian uint16
  console.log('Sig length field (little-endian):', sigLenLE);
  
  const nonceByte = kernel._getCryptoNonceByte(); // 40
  const nonce = signMsg.subarray(2, 2 + nonceByte);
  console.log('Nonce (bytes 2-41):', util.uint8ArrayToString(nonce));
  
  const compSig = signMsg.subarray(2 + nonceByte);
  console.log('Compressed sig starts at byte:', 2 + nonceByte);
  console.log('Compressed sig length:', compSig.length);
  console.log('First 20 bytes of compressed sig:', Array.from(compSig.subarray(0, 20)));
  console.log('Header byte:', '0x' + compSig[0].toString(16));
  
  // Falcon standard: header = 0x20 + logn for ct1 encoding
  // header = 0x30 + logn for ct0 encoding  
  // For n=512, logn=9
  // 0x20 + 9 = 0x29 = 41 -- THIS IS IT! ct1 encoding!
  console.log('\n=== ENCODING TYPE ===');
  const header = compSig[0];
  const logn = header & 0x0F;
  const encType = (header >> 4) & 0x0F;
  console.log('logn:', logn, '(expected 9 for n=512)');
  console.log('encoding type:', encType, '(2=ct1, 3=ct0)');
  console.log('n:', 1 << logn);
  
  // Verify the sig works
  console.log('\nVerify:', Falcon512.verify(signMsg, msg, keypair.pk));
  
  // Now let's decode the public key
  console.log('\n=== PUBLIC KEY DECODE ===');
  const pk = keypair.pk;
  console.log('pk header:', '0x' + pk[0].toString(16));
  // pk header should be 0x00 + logn
  const pkLogn = pk[0] & 0x0F;
  console.log('pk logn:', pkLogn);
  
  // pk coefficients are 14-bit packed (q=12289, ceil(log2(12289))=14)
  // After 1 header byte, we have n * 14 / 8 = 512 * 14 / 8 = 896 bytes
  console.log('pk data bytes:', pk.length - 1, '(expected:', 512 * 14 / 8, ')');
  
  // Decode pk: read 14-bit values from byte stream
  function decodePk14bit(pkBytes, n) {
    const coeffs = [];
    let acc = 0;
    let accLen = 0;
    let idx = 1; // skip header
    for (let i = 0; i < n; i++) {
      while (accLen < 14) {
        acc |= pkBytes[idx++] << accLen;
        accLen += 8;
      }
      coeffs.push(acc & 0x3FFF); // 14 bits
      acc >>= 14;
      accLen -= 14;
    }
    return coeffs;
  }
  
  const pkCoeffs = decodePk14bit(pk, 512);
  console.log('Decoded pk coefficients (first 10):', pkCoeffs.slice(0, 10));
  console.log('All < 12289:', pkCoeffs.every(c => c < 12289));
  console.log('All >= 0:', pkCoeffs.every(c => c >= 0));
})();
