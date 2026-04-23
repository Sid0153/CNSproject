import forge from 'node-forge';

// Generate Random AES Key
export function generateAESKey() {
  return forge.util.bytesToHex(forge.random.getBytesSync(32));
}

// Encrypt AES key using Server's RSA Public Key (PEM format)
export function encryptRSA(publicKeyPem, dataHex) {
  const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
  const dataBytes = forge.util.hexToBytes(dataHex);
  
  // Use RSA-OAEP
  const encrypted = publicKey.encrypt(dataBytes, 'RSA-OAEP', {
    md: forge.md.sha256.create(),
    mgf1: {
      md: forge.md.sha256.create()
    }
  });
  
  return forge.util.bytesToHex(encrypted);
}

// Generate DH keys using server parameters
export function generateDHKeys(primeHex, generatorHex) {
  const prime = new forge.jsbn.BigInteger(primeHex, 16);
  const generator = new forge.jsbn.BigInteger(generatorHex, 16);
  
  // Create DH object and generate keys
  // For node-forge, doing raw DH is tricky, but we can do it via forge.jsbn
  // Actually, wait: node-forge doesn't have a direct `forge.dh` API for arbitrary DH in browser without full ASN.1.
  // Wait, let's just do a simplified manual DH or see if node-forge has it.
  // It has forge.pki.createDiffieHellman? No.
  // Let's implement basic JSBN DH:
  
  // Generate random private key (a)
  const aBytes = forge.random.getBytesSync(128); // 1024 bit max
  const a = new forge.jsbn.BigInteger(forge.util.bytesToHex(aBytes), 16);
  
  // public key = g^a mod p
  const publicKey = generator.modPow(a, prime);
  
  return {
    privateKey: a,
    publicKeyHex: publicKey.toString(16)
  };
}

export function computeDHSecret(privateKey, serverPublicKeyHex, primeHex) {
  const prime = new forge.jsbn.BigInteger(primeHex, 16);
  const serverPublicKey = new forge.jsbn.BigInteger(serverPublicKeyHex, 16);
  
  // secret = (serverPubKey)^a mod p
  const secret = serverPublicKey.modPow(privateKey, prime);
  return secret.toString(16);
}

// AES Encryption
export function encryptAES(text, keyHex) {
  const key = forge.util.hexToBytes(keyHex);
  const iv = forge.random.getBytesSync(16);
  
  const cipher = forge.cipher.createCipher('AES-CBC', key);
  cipher.start({ iv: iv });
  cipher.update(forge.util.createBuffer(text, 'utf8'));
  cipher.finish();
  
  return {
    iv: forge.util.bytesToHex(iv),
    encryptedData: cipher.output.toHex()
  };
}

// AES Decryption
export function decryptAES(encryptedDataHex, keyHex, ivHex) {
  const key = forge.util.hexToBytes(keyHex);
  const iv = forge.util.hexToBytes(ivHex);
  
  const decipher = forge.cipher.createDecipher('AES-CBC', key);
  decipher.start({ iv: iv });
  decipher.update(forge.util.createBuffer(forge.util.hexToBytes(encryptedDataHex)));
  decipher.finish();
  
  return decipher.output.toString('utf8');
}

// SHA-256 Hash
export function generateHash(data) {
  const md = forge.md.sha256.create();
  md.update(data, 'utf8');
  return md.digest().toHex();
}
