const { getKernel, util } = require('falcon-sign');

// Decode Falcon-512 public key from bytes to polynomial coefficients mod q
// Falcon pk format: 1 header byte + ceil(n * 14 / 8) bytes of 14-bit packed coefficients
function decodePk(pkBytes, n = 512, logq = 14) {
  const coeffs = [];
  let bitBuf = 0;
  let bitCount = 0;
  let byteIdx = 1; // skip header byte
  
  for (let i = 0; i < n; i++) {
    while (bitCount < logq) {
      bitBuf |= pkBytes[byteIdx++] << bitCount;
      bitCount += 8;
    }
    coeffs.push(bitBuf & ((1 << logq) - 1));
    bitBuf >>= logq;
    bitCount -= logq;
  }
  return coeffs;
}

// Decode Falcon compressed signature to polynomial coefficients
// Falcon sig format: [2-byte length][40-byte nonce][compressed s2]
// The compressed format uses a combination of Huffman-like encoding
// Actually, falcon signatures use a specific encoding defined in the spec
// Let me check the actual format used by this WASM implementation

function decodeCompressedSig(sigBytes, n = 512) {
  // Skip 2-byte length header and 40-byte nonce
  const compStart = 42;
  const comp = sigBytes.subarray(compStart);
  
  // Falcon compressed signature decoding
  // Header byte in compressed portion tells the encoding method
  const header = comp[0];
  console.log('Compressed sig header byte:', header.toString(16), '=', header);
  console.log('Expected: 0x30 + logn, for n=512 logn=9, so 0x39 =', 0x39);
  
  if ((header & 0xF0) !== 0x30) {
    console.log('WARNING: unexpected header format');
  }
  
  // After header, coefficients are encoded using a specific scheme
  // Each coefficient is stored as sign bit + absolute value in unary/binary
  const coeffs = new Array(n);
  let bitIdx = 0;
  let byteIdx = 1; // skip header
  
  function readBit() {
    let bit = (comp[byteIdx] >> (7 - bitIdx)) & 1;
    bitIdx++;
    if (bitIdx >= 8) { bitIdx = 0; byteIdx++; }
    return bit;
  }
  
  // Falcon uses a specific encoding:
  // For each coefficient:
  //   - low bits: (logn - 1) bits as binary
  //   - high bits: unary coding (count of 0s terminated by 1)
  //   - sign bit: 1 bit (0=positive, 1=negative)
  const logn = 9;
  const lowBits = logn - 1; // 8 bits
  
  for (let i = 0; i < n; i++) {
    // Read sign bit
    let sign = readBit();
    
    // Read low bits (8 bits for falcon-512)
    let low = 0;
    for (let j = lowBits - 1; j >= 0; j--) {
      low |= readBit() << j;
    }
    
    // Read high bits (unary: count zeros until 1)
    let high = 0;
    while (readBit() === 0) {
      high++;
    }
    
    let value = (high << lowBits) | low;
    if (sign && value !== 0) {
      value = 12289 - value; // Convert to mod q representation
    }
    coeffs[i] = value;
  }
  
  return coeffs;
}

(async () => {
  const Falcon512 = await getKernel('falcon512_n3_v1');
  const keypair = Falcon512.genkey();
  
  // Decode public key
  const pkCoeffs = decodePk(keypair.pk);
  console.log('=== DECODED PUBLIC KEY ===');
  console.log('num coefficients:', pkCoeffs.length);
  console.log('first 10:', pkCoeffs.slice(0, 10));
  console.log('all in range [0, 12288]:', pkCoeffs.every(c => c >= 0 && c < 12289));
  
  // Sign
  const salt = util.randomBytes(20);
  const msg = 'test';
  const signMsg = Falcon512.sign(msg, keypair.sk, salt);
  
  console.log('\n=== SIGNATURE ===');
  console.log('total bytes:', signMsg.length);
  
  // Extract nonce (salt) - bytes 2..41
  const nonce = signMsg.subarray(2, 42);
  console.log('nonce (40 bytes):', util.uint8ArrayToString(nonce));
  console.log('input salt (20 bytes):', util.uint8ArrayToString(salt));
  
  // Try to decode s2 coefficients
  try {
    const s2 = decodeCompressedSig(signMsg);
    console.log('\n=== DECODED s2 ===');
    console.log('num coefficients:', s2.length);
    console.log('first 20:', s2.slice(0, 20));
    console.log('all in range [0, 12288]:', s2.every(c => c >= 0 && c < 12289));
  } catch(e) {
    console.log('Decode error:', e.message);
  }
  
  // Verify still works
  console.log('\nverify:', Falcon512.verify(signMsg, msg, keypair.pk));
})();
