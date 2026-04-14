const { getKernel, util } = require('falcon-sign');

// ============================================================
// PUBLIC KEY DECODING
// Falcon public key: 1 header byte + n coefficients packed as 14-bit big-endian
// ============================================================
function decodeFalconPk(pkBytes, n = 512) {
  const coeffs = [];
  let acc = 0;
  let accLen = 0;
  let idx = 1; // skip header byte
  
  for (let i = 0; i < n; i++) {
    // Read bits in big-endian order (MSB first)
    while (accLen < 14) {
      acc = (acc << 8) | pkBytes[idx++];
      accLen += 8;
    }
    accLen -= 14;
    coeffs.push((acc >> accLen) & 0x3FFF);
  }
  return coeffs;
}

// ============================================================
// SIGNATURE DECODING (ct1 format)
// Falcon ct1 encoding: each coefficient encoded as:
//   - sign bit (1 bit): 0 = positive, 1 = negative
//   - low bits (8 bits for falcon-512): binary
//   - high bits: unary (count of 0s terminated by 1)
// Bits are read MSB-first within each byte
// ============================================================
function decodeFalconSigCt1(sigBytes, n = 512, q = 12289) {
  // Skip 2-byte length + 40-byte nonce
  const comp = sigBytes.subarray(42);
  const header = comp[0];
  const logn = header & 0x0F;
  
  if (logn !== 9 || (1 << logn) !== n) {
    throw new Error(`Unexpected logn: ${logn}`);
  }
  
  // ct1 format: each coeff is encoded as sign + low + high (unary)
  let bytePos = 1; // skip header
  let bitPos = 0;  // bits read from current byte (0..7, MSB first)
  
  function readBit() {
    if (bytePos >= comp.length) return 0;
    const bit = (comp[bytePos] >> (7 - bitPos)) & 1;
    bitPos++;
    if (bitPos >= 8) {
      bitPos = 0;
      bytePos++;
    }
    return bit;
  }
  
  const coeffs = new Array(n);
  
  for (let i = 0; i < n; i++) {
    // Read sign bit
    const sign = readBit();
    
    // Read low bits (logn - 1 = 8 bits for falcon-512)
    const lowBits = logn - 1; // 8
    let low = 0;
    for (let j = lowBits - 1; j >= 0; j--) {
      low |= readBit() << j;
    }
    
    // Read high bits (unary: count 0s until 1)
    let high = 0;
    while (readBit() === 0) {
      high++;
    }
    
    // Reconstruct absolute value
    const absVal = (high << lowBits) | low;
    
    // Apply sign: if sign=1 and value!=0, negate mod q
    if (sign === 1 && absVal !== 0) {
      coeffs[i] = q - absVal;
    } else {
      coeffs[i] = absVal;
    }
  }
  
  return coeffs;
}

// Extract 40-byte nonce from signature
function extractNonce(sigBytes) {
  return sigBytes.subarray(2, 42);
}

(async () => {
  const Falcon512 = await getKernel('falcon512_n3_v1');
  const keypair = Falcon512.genkey();
  
  // Decode public key
  const pkCoeffs = decodeFalconPk(keypair.pk);
  console.log('=== PUBLIC KEY ===');
  console.log('coefficients:', pkCoeffs.length);
  console.log('first 10:', pkCoeffs.slice(0, 10));
  console.log('all in [0, 12289):', pkCoeffs.every(c => c >= 0 && c < 12289));
  
  // Sign a message
  const salt = util.randomBytes(20);
  const msg = 'hello falcon';
  const signMsg = Falcon512.sign(msg, keypair.sk, salt);
  
  console.log('\n=== SIGNATURE DECODE ===');
  try {
    const s2 = decodeFalconSigCt1(signMsg);
    console.log('s2 coefficients:', s2.length);
    console.log('first 20:', s2.slice(0, 20));
    console.log('all in [0, 12289):', s2.every(c => c >= 0 && c < 12289));
    
    const nonce = extractNonce(signMsg);
    console.log('nonce (40 bytes):', util.uint8ArrayToString(nonce));
    
    // Verify roundtrip with JS
    console.log('\nJS verify:', Falcon512.verify(signMsg, msg, keypair.pk));
    
    // Now test with the hardcoded test vector to confirm our decoder matches
    console.log('\n=== VALIDATION: sign multiple times, check consistency ===');
    const sign2 = Falcon512.sign(msg, keypair.sk, salt);
    const s2_2 = decodeFalconSigCt1(sign2);
    const match = s2.every((v, i) => v === s2_2[i]);
    console.log('Same salt produces same s2:', match);
    
  } catch(e) {
    console.error('Decode failed:', e.message);
    console.error(e.stack);
  }
})();
