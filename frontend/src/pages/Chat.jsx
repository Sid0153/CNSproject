import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { io } from 'socket.io-client';
import { 
  generateAESKey, 
  encryptRSA, 
  generateDHKeys, 
  computeDHSecret, 
  encryptAES, 
  decryptAES, 
  generateHash 
} from '../utils/cryptoClient';
import SecurityPanel from '../components/SecurityPanel';

function Chat() {
  const [socket, setSocket] = useState(null);
  const [messages, setMessages] = useState([]);
  const [inputText, setInputText] = useState('');
  const [aesKey, setAesKey] = useState(null);
  const [dhSecret, setDhSecret] = useState(null);
  
  // Security Panel State
  const [securityData, setSecurityData] = useState({
    keysEstablished: false,
    lastSentEncrypted: '',
    lastSentHash: '',
    lastReceivedEncrypted: '',
    lastReceivedDecrypted: '',
    lastReceivedHash: '',
  });

  const navigate = useNavigate();
  const username = localStorage.getItem('username');
  const token = localStorage.getItem('token');
  const messagesEndRef = useRef(null);

  useEffect(() => {
    if (!token || !username) {
      navigate('/login');
      return;
    }

    const API_URL = import.meta.env.DEV ? 'http://localhost:5000' : undefined;
    const newSocket = io(API_URL);
    setSocket(newSocket);

    // 1. Receive Server Keys
    newSocket.on('server_keys', (serverKeys) => {
      try {
        const { rsaPublicKey, dhPublicKey, dhPrime, dhGenerator } = serverKeys;
        
        // 2. Generate Client DH Keys and Compute DH Secret
        const dhClient = generateDHKeys(dhPrime, dhGenerator);
        const secret = computeDHSecret(dhClient.privateKey, dhPublicKey, dhPrime);
        setDhSecret(secret);
        
        // 3. Generate AES Session Key
        const newAesKey = generateAESKey();
        setAesKey(newAesKey);

        // 4. Encrypt AES Session Key with Server's RSA Public Key
        const encryptedAESKey = encryptRSA(rsaPublicKey, newAesKey);

        // 5. Send Client Keys back to Server
        newSocket.emit('client_keys', {
          username,
          clientDHPublicKey: dhClient.publicKeyHex,
          encryptedAESKey
        });

        setSecurityData(prev => ({
          ...prev,
          keysEstablished: true,
          dhSharedSecret: secret.substring(0, 32) + '...',
          aesSessionKey: newAesKey.substring(0, 32) + '...'
        }));

      } catch (error) {
        console.error('Key exchange error:', error);
      }
    });

    // Handle Chat History (encrypted)
    newSocket.on('chat_history', (encryptedHistory) => {
      // Need to wait until aesKey is set before decrypting.
      // A small timeout or dependency check could be needed, 
      // but state updates are async. Let's rely on aesKey from the scope if possible.
      // Actually, aesKey might not be in the current closure. 
      // We'll store aesKey in a ref as well to ensure the socket listener can access it.
    });

    return () => newSocket.close();
  }, [navigate, token, username]);

  // Use a ref for aesKey to access it inside socket listeners reliably
  const aesKeyRef = useRef(null);
  useEffect(() => {
    aesKeyRef.current = aesKey;
  }, [aesKey]);

  useEffect(() => {
    if (!socket) return;

    const handleHistory = (encryptedHistory) => {
      if (!aesKeyRef.current) return; // safety check
      
      try {
        const decryptedHistory = encryptedHistory.map(msg => {
          const decryptedPayload = decryptAES(msg.encryptedData, aesKeyRef.current, msg.iv);
          return JSON.parse(decryptedPayload);
        });
        setMessages(decryptedHistory);
      } catch (error) {
        console.error('Error decrypting history:', error);
      }
    };

    const handleReceiveMessage = (data) => {
      if (!aesKeyRef.current) return;
      try {
        const { iv, encryptedData, hash } = data;
        
        // Decrypt
        const decryptedPayloadString = decryptAES(encryptedData, aesKeyRef.current, iv);
        
        // Verify Hash
        const computedHash = generateHash(decryptedPayloadString);
        if (computedHash !== hash) {
          console.error('Hash mismatch! Message tampered.');
          return;
        }

        const payload = JSON.parse(decryptedPayloadString);
        
        setSecurityData(prev => ({
          ...prev,
          lastReceivedEncrypted: encryptedData,
          lastReceivedDecrypted: payload.message,
          lastReceivedHash: hash,
          hashVerified: computedHash === hash
        }));

        setMessages(prev => [...prev, payload]);
      } catch (error) {
        console.error('Error handling received message:', error);
      }
    };

    socket.on('chat_history', handleHistory);
    socket.on('receive_message', handleReceiveMessage);

    return () => {
      socket.off('chat_history', handleHistory);
      socket.off('receive_message', handleReceiveMessage);
    };
  }, [socket, aesKey]); // Re-bind when aesKey is available

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSendMessage = (e) => {
    e.preventDefault();
    if (!inputText.trim() || !aesKey) return;

    const payload = JSON.stringify({
      message: inputText,
      timestamp: new Date().toISOString()
    });

    // 1. Hash the payload
    const hash = generateHash(payload);

    // 2. Encrypt the payload
    const { iv, encryptedData } = encryptAES(payload, aesKey);

    // Update Security Panel
    setSecurityData(prev => ({
      ...prev,
      lastSentEncrypted: encryptedData,
      lastSentHash: hash,
      lastSentPlaintext: inputText
    }));

    // 3. Send via Socket
    socket.emit('send_message', { iv, encryptedData, hash });
    
    setInputText('');
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    navigate('/login');
  };

  return (
    <div className="chat-layout">
      {/* Left Column: Chat UI */}
      <div className="chat-section glass-panel">
        <div className="chat-header">
          <h2>Secure Chat Room</h2>
          <div>
            <span style={{marginRight: '15px', color: 'var(--text-muted)'}}>Logged in as: <strong>{username}</strong></span>
            <button className="logout-btn" onClick={handleLogout}>Logout</button>
          </div>
        </div>
        
        <div className="messages-container">
          {messages.map((msg, index) => (
            <div key={index} className={`message ${msg.username === username ? 'self' : 'other'}`}>
              <div className="message-meta">
                <span>{msg.username}</span>
                <span>{new Date(msg.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
              </div>
              <div className="message-bubble">
                {msg.message}
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>
        
        <form className="chat-input-area" onSubmit={handleSendMessage}>
          <input 
            type="text" 
            placeholder="Type a secure message..." 
            value={inputText}
            onChange={e => setInputText(e.target.value)}
            disabled={!securityData.keysEstablished}
            autoComplete="off"
          />
          <button type="submit" className="send-btn" disabled={!securityData.keysEstablished}>Send</button>
        </form>
      </div>

      {/* Right Column: Security Demonstration Panel */}
      <SecurityPanel data={securityData} />
    </div>
  );
}

export default Chat;
