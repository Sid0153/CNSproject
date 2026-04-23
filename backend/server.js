const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');
const cors = require('cors');
require('dotenv').config();

const { generateRSAKeyPair, generateDH } = require('./crypto/cryptoUtils');
const authController = require('./auth/authController');
const socketHandler = require('./sockets/socketHandler');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

app.use(cors());
app.use(express.json());

// Routes
app.post('/api/signup', authController.signup);
app.post('/api/login', authController.login);

// Serve frontend in production
app.use(express.static(path.join(__dirname, '../frontend/dist')));
app.use((req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/dist/index.html'));
});

// Generate Server Keys on Startup
console.log('--- Initializing Server Cryptography ---');
const serverRSAKeys = generateRSAKeyPair();
console.log('[Demo] Server RSA Key Pair Generated');
const serverDHParams = generateDH();
console.log('[Demo] Server Diffie-Hellman Parameters Generated');
console.log('----------------------------------------\n');

// Initialize Socket Handler
socketHandler(io, serverRSAKeys, serverDHParams);

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
