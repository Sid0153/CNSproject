const crypto = require('crypto');

// RSA Key Pair Generation
function generateRSAKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  return { publicKey, privateKey };
}

// RSA Decryption (Server decrypts AES key sent by client)
function decryptRSA(privateKeyPem, encryptedDataHex) {
  const encryptedBuffer = Buffer.from(encryptedDataHex, 'hex');
  const decryptedBuffer = crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    encryptedBuffer
  );
  return decryptedBuffer.toString('hex'); // AES key in hex
}

// Diffie-Hellman Setup
function generateDH() {
  // Use a standard 2048-bit MODP Group or generate a prime
  // For demo, generating a small 512-bit prime is faster, but let's use 1024 for balance.
  const dh = crypto.createDiffieHellman(1024);
  dh.generateKeys();
  return {
    dh,
    prime: dh.getPrime('hex'),
    generator: dh.getGenerator('hex'),
    publicKey: dh.getPublicKey('hex')
  };
}

function computeDHSecret(dh, clientPublicKeyHex) {
  const secret = dh.computeSecret(clientPublicKeyHex, 'hex', 'hex');
  return secret;
}

// AES Encryption/Decryption (Optional if server needs to decrypt)
function encryptAES(text, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted
  };
}

function decryptAES(encryptedDataHex, keyHex, ivHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedDataHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// SHA-256 Hash
function generateHash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = {
  generateRSAKeyPair,
  decryptRSA,
  generateDH,
  computeDHSecret,
  encryptAES,
  decryptAES,
  generateHash
};
