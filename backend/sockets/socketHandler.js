const { 
  decryptRSA, 
  computeDHSecret, 
  decryptAES, 
  encryptAES, 
  generateHash 
} = require('../crypto/cryptoUtils');

// Store client keys: socketId -> { username, aesKey, dhSecret }
const clientSessions = {};
const chatHistory = []; // { username, message, timestamp }

module.exports = (io, serverKeys, dhParams) => {
  io.on('connection', (socket) => {
    console.log(`[Socket] User connected: ${socket.id}`);

    // 1. Send Server Keys to Client
    socket.emit('server_keys', {
      rsaPublicKey: serverKeys.publicKey,
      dhPublicKey: dhParams.publicKey,
      dhPrime: dhParams.prime,
      dhGenerator: dhParams.generator
    });

    // 2. Receive Client Keys (DH and RSA-encrypted AES key)
    socket.on('client_keys', (data) => {
      try {
        const { username, clientDHPublicKey, encryptedAESKey } = data;
        
        // Decrypt the AES key using Server's RSA Private Key
        const aesKeyHex = decryptRSA(serverKeys.privateKey, encryptedAESKey);
        
        // Compute DH Shared Secret (for demonstration purposes)
        const dhSecretHex = computeDHSecret(dhParams.dh, clientDHPublicKey);

        console.log(`\n--- Key Exchange Completed for ${username} (${socket.id}) ---`);
        console.log(`[Demo] DH Shared Secret (Hex): ${dhSecretHex.substring(0, 32)}...`);
        console.log(`[Demo] Decrypted AES Key (Hex): ${aesKeyHex}`);
        console.log(`----------------------------------------------------\n`);

        clientSessions[socket.id] = {
          username,
          aesKey: aesKeyHex,
          dhSecret: dhSecretHex
        };

        // Send chat history to the newly connected client
        // The server encrypts the history using the client's specific AES key
        const encryptedHistory = chatHistory.map(msg => {
          const payload = JSON.stringify(msg);
          const hash = generateHash(payload);
          const { iv, encryptedData } = encryptAES(payload, aesKeyHex);
          return { iv, encryptedData, hash };
        });

        socket.emit('chat_history', encryptedHistory);

      } catch (error) {
        console.error('[Socket] Key exchange error:', error);
      }
    });

    // 3. Handle incoming encrypted messages
    socket.on('send_message', (data) => {
      try {
        const session = clientSessions[socket.id];
        if (!session) return;

        const { iv, encryptedData, hash } = data;

        // Decrypt message
        const decryptedPayloadString = decryptAES(encryptedData, session.aesKey, iv);
        
        // Verify Hash
        const computedHash = generateHash(decryptedPayloadString);
        if (computedHash !== hash) {
          console.error(`[Security Alert] Hash mismatch from ${session.username}! Message tampered.`);
          return;
        }

        const payload = JSON.parse(decryptedPayloadString);
        console.log(`[Demo] Received encrypted msg from ${session.username}. Verified Hash: ${hash}`);
        console.log(`[Demo] Decrypted: ${payload.message}`);

        // Store in history
        const messageRecord = {
          username: session.username,
          message: payload.message,
          timestamp: payload.timestamp
        };
        chatHistory.push(messageRecord);

        // Broadcast to all clients (including sender so they see it confirmed)
        const broadcastPayloadString = JSON.stringify(messageRecord);
        
        // We must encrypt it individually for each connected client with their unique AES key
        const allSockets = io.sockets.sockets;
        allSockets.forEach((clientSocket) => {
          const targetSession = clientSessions[clientSocket.id];
          if (targetSession) {
            const targetHash = generateHash(broadcastPayloadString);
            const encryptedBroadcast = encryptAES(broadcastPayloadString, targetSession.aesKey);
            clientSocket.emit('receive_message', {
              iv: encryptedBroadcast.iv,
              encryptedData: encryptedBroadcast.encryptedData,
              hash: targetHash
            });
          }
        });

      } catch (error) {
        console.error('[Socket] Message handling error:', error);
      }
    });

    socket.on('disconnect', () => {
      console.log(`[Socket] User disconnected: ${socket.id}`);
      delete clientSessions[socket.id];
    });
  });
};
