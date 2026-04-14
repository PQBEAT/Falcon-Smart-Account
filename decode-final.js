const { getKernel, util } = require('falcon-sign');

// ============================================================
// PUBLIC KEY DECODING (modq_decode from Falcon spec)
// Big-endian 14-bit packed coefficients, 1 header byte
// ============================================================
function decodeFalconPk(pkBytes, n = 512) {
  const coeffs = [];
  let acc = 0;
  let accLen = 0;
  let idx = 1; // skip header
  let u = 0;
  while (u < n) {
    acc = (acc << 8) | pkBytes[idx++];
    accLen += 8;
    if (accLen >= 14) {
      accLen -= 14;
      const w = (acc >>> accLen) & 0x3FFF;
      if (w >= 12289) throw new Error(`pk coeff ${u} out of range: ${w}`);
      coeffs.push(w);
      u++;
    }
  }
  return coeffs;
}

// ============================================================
// SIGNATURE DECODING (comp_decode from Falcon spec)
// Exact port of PQCLEAN_FALCON512_CLEAN_comp_decode
// Returns signed int16 values (can be negative)
// ============================================================
function decodeFalconSig(compData, n = 512) {
  // compData is the compressed bytes AFTER the header byte
  const buf = compData;
  const maxLen = buf.length;
  const x = new Array(n);
  let acc = 0;
  let accLen = 0;
  let v = 0;
  
  for (let u = 0; u < n; u++) {
    // Get next 8 bits: sign (1 bit) + low 7 bits of absolute value
    if (v >= maxLen) throw new Error('Unexpected end of signature data');
    acc = ((acc << 8) | buf[v++]) >>> 0; // unsigned
    const b = (acc >>> accLen) & 0xFF;
    const s = b & 128; // sign bit
    let m = b & 127;   // low 7 bits of |value|
    
    // Get additional high bits via unary: count 0s until 1
    for (;;) {
      if (accLen === 0) {
        if (v >= maxLen) throw new Error('Unexpected end of signature data');
        acc = ((acc << 8) | buf[v++]) >>> 0;
        accLen = 8;
      }
      accLen--;
      if (((acc >>> accLen) & 1) !== 0) {
        break;
      }
      m += 128;
      if (m > 2047) throw new Error(`Coefficient too large at index ${u}`);
    }
    
    // "-0" is forbidden
    if (s && m === 0) throw new Error(`Forbidden -0 at index ${u}`);
    
    x[u] = s ? -m : m;
  }
  
  return x;
}

// Convert signed coefficients to mod q representation (matching Solidity)
function toModQ(signedCoeffs, q = 12289) {
  return signedCoeffs.map(c => c < 0 ? q + c : c);
}

// Extract nonce (40 bytes) from full signature
function extractNonce(sigBytes) {
  return sigBytes.subarray(2, 42);
}

// Full decode pipeline
function decodeFalconSignature(sigBytes, n = 512) {
  const nonce = extractNonce(sigBytes);
  const compData = sigBytes.subarray(43); // skip 2 len + 40 nonce + 1 header
  const signedS2 = decodeFalconSig(compData, n);
  const s2 = toModQ(signedS2);
  return { s2, nonce, signedS2 };
}

// ============================================================
// TEST
// ============================================================
(async () => {
  const Falcon512 = await getKernel('falcon512_n3_v1');
  
  // Test pk decoding
  const keypair = Falcon512.genkey();
  const pkCoeffs = decodeFalconPk(keypair.pk);
  console.log('=== PUBLIC KEY ===');
  console.log('coefficients:', pkCoeffs.length);
  console.log('first 10:', pkCoeffs.slice(0, 10));
  console.log('all in [0,12289):', pkCoeffs.every(c => c >= 0 && c < 12289));
  
  // Test sig decoding
  const salt = util.randomBytes(20);
  const msg = 'hello falcon';
  const signMsg = Falcon512.sign(msg, keypair.sk, salt);
  
  console.log('\n=== SIGNATURE ===');
  console.log('total bytes:', signMsg.length);
  
  const { s2, nonce, signedS2 } = decodeFalconSignature(signMsg);
  console.log('s2 length:', s2.length);
  console.log('first 20 (mod q):', s2.slice(0, 20));
  console.log('first 20 (signed):', signedS2.slice(0, 20));
  console.log('all in [0,12289):', s2.every(c => c >= 0 && c < 12289));
  console.log('nonce:', util.uint8ArrayToString(nonce));
  
  // Verify round-trip with same salt
  const sign2 = Falcon512.sign(msg, keypair.sk, salt);
  const { s2: s2b } = decodeFalconSignature(sign2);
  console.log('\nSame-salt consistency:', s2.every((v, i) => v === s2b[i]));
  
  // Verify still valid
  console.log('JS verify:', Falcon512.verify(signMsg, msg, keypair.pk));
  
  console.log('\n=== FULL DECODE SUCCESS ===');
  console.log('pk: 897 bytes -> 512 uint coefficients mod 12289');
  console.log('sig: compressed bytes -> 512 signed int16 -> 512 uint mod 12289 + 40-byte nonce');
})();
