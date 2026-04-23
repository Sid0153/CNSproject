function SecurityPanel({ data }) {
  return (
    <div className="security-panel glass-panel">
      <div className="security-header">
        <div className={`status-dot ${data.keysEstablished ? '' : 'offline'}`} style={{ backgroundColor: data.keysEstablished ? 'var(--success)' : 'var(--error)', boxShadow: `0 0 8px ${data.keysEstablished ? 'var(--success)' : 'var(--error)'}`}}></div>
        <h2>Security Dashboard</h2>
      </div>
      
      <div className="security-content">
        <div className="sec-block">
          <div className="sec-title">Key Exchange Status</div>
          <div className={`sec-data ${data.keysEstablished ? 'highlight' : ''}`}>
            {data.keysEstablished ? 'SUCCESS: RSA-encrypted AES key sent. DH Secret derived.' : 'PENDING...'}
          </div>
        </div>

        {data.keysEstablished && (
          <>
            <div className="sec-block">
              <div className="sec-title">DH Shared Secret (Demo)</div>
              <div className="sec-data mono">{data.dhSharedSecret}</div>
            </div>
            <div className="sec-block">
              <div className="sec-title">AES Session Key</div>
              <div className="sec-data mono">{data.aesSessionKey}</div>
            </div>
          </>
        )}

        <div className="sec-block" style={{marginTop: '40px', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '20px'}}>
          <div className="sec-title" style={{color: '#a5b4fc'}}>Last Outgoing Message</div>
        </div>

        <div className="sec-block">
          <div className="sec-title">1. Plaintext</div>
          <div className="sec-data">{data.lastSentPlaintext || 'No messages sent'}</div>
        </div>

        <div className="sec-block">
          <div className="sec-title">2. SHA-256 Hash</div>
          <div className="sec-data mono">{data.lastSentHash ? data.lastSentHash.substring(0, 32) + '...' : '-'}</div>
        </div>

        <div className="sec-block">
          <div className="sec-title">3. AES Encrypted Payload</div>
          <div className="sec-data mono">{data.lastSentEncrypted ? data.lastSentEncrypted.substring(0, 64) + '...' : '-'}</div>
        </div>

        <div className="sec-block" style={{marginTop: '40px', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '20px'}}>
          <div className="sec-title" style={{color: '#a5b4fc'}}>Last Incoming Message</div>
        </div>

        <div className="sec-block">
          <div className="sec-title">1. Encrypted Payload Received</div>
          <div className="sec-data mono">{data.lastReceivedEncrypted ? data.lastReceivedEncrypted.substring(0, 64) + '...' : 'No messages received'}</div>
        </div>

        <div className="sec-block">
          <div className="sec-title">2. Decrypted Content</div>
          <div className="sec-data">{data.lastReceivedDecrypted || '-'}</div>
        </div>

        <div className="sec-block">
          <div className="sec-title">
            3. Hash Verification
            {data.hashVerified !== undefined && (
              <span style={{color: data.hashVerified ? 'var(--success)' : 'var(--error)'}}>
                {data.hashVerified ? ' (MATCH)' : ' (MISMATCH)'}
              </span>
            )}
          </div>
          <div className="sec-data mono">{data.lastReceivedHash ? data.lastReceivedHash.substring(0, 32) + '...' : '-'}</div>
        </div>

      </div>
    </div>
  );
}

export default SecurityPanel;
