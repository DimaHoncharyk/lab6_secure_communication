
import { useState } from "react";
import "./App.css";

const API = "";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function fromBase64(value) {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API}${path}`, options);

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`HTTP ${response.status}: ${error}`);
  }

  return response.json();
}

async function establishSession() {
  const { id } = await apiRequest(
    "/api/crypto-keys/generate/rsa-keys",
    { method: "POST" }
  );

  const { public_key } = await apiRequest(
    `/api/crypto-keys/rsa-public-key/${id}`
  );

  const rsaKey = await crypto.subtle.importKey(
    "spki",
    fromBase64(public_key),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );

  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const rawKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", aesKey)
  );

  const sessionId = crypto.randomUUID();

  const sessionData = JSON.stringify({
    session_id: sessionId,
    aes_key: {
      key: toBase64(rawKey),
      iv: toBase64(crypto.getRandomValues(new Uint8Array(12)))
    }
  });

  const encryptedSession = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    rsaKey,
    encoder.encode(sessionData)
  );

  await apiRequest("/api/sessions/init", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-rsa-id": String(id)
    },
    body: JSON.stringify({
      encrypted_data: toBase64(new Uint8Array(encryptedSession))
    })
  });

  return { sessionId, rsaId: id, aesKey };
}

async function sendEncryptedMessage(session, message) {
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    session.aesKey,
    encoder.encode(message)
  );

  const encryptedText = toBase64(new Uint8Array(encrypted));

  const response = await apiRequest("/api/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-session-id": session.sessionId
    },
    body: JSON.stringify({
      iv: toBase64(iv),
      encrypted_message: encryptedText
    })
  });

  if (response.session_id !== session.sessionId) {
    throw new Error("Session ID mismatch");
  }

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: fromBase64(response.iv)
    },
    session.aesKey,
    fromBase64(response.encrypted_message)
  );

  return {
    encryptedText,
    responseText: decoder.decode(decrypted),
    encryptedResponse: response.encrypted_message
  };
}

export default function App() {
  const [session, setSession] = useState(null);
  const [status, setStatus] = useState("disconnected");
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [showEncrypted, setShowEncrypted] = useState(true);

  async function connect() {
    setBusy(true);
    setError("");
    setStatus("connecting");
    setSession(null);
    setMessages([]);

    try {
      const newSession = await establishSession();
      setSession(newSession);
      setStatus("connected");
    } catch (err) {
      setStatus("disconnected");
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleSend(event) {
    event.preventDefault();
    if (!session || !input.trim() || busy) return;

    const message = input.trim();
    setInput("");
    setBusy(true);
    setError("");

    try {
      const result = await sendEncryptedMessage(session, message);

      setMessages((previous) => [
        ...previous,
        {
          id: crypto.randomUUID(),
          type: "user",
          text: message,
          encrypted: result.encryptedText
        },
        {
          id: crypto.randomUUID(),
          type: "server",
          text: result.responseText,
          encrypted: result.encryptedResponse
        }
      ]);
    } catch (err) {
      setInput(message);
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-icon">◆</span>
          <div>
            <h2>SecureChat</h2>
            <small>LABORATORY №6</small>
          </div>
        </div>

        <div className="sidebar-section">
          <span className="section-label">CONNECTION STATUS</span>
          <div className={`connection-status ${status}`}>
            <span className="status-dot" />
            {status === "connected"
              ? "Secure connection"
              : status === "connecting"
              ? "Connecting..."
              : "Disconnected"}
          </div>
        </div>

        <div className="sidebar-section">
          <span className="section-label">CRYPTOGRAPHY</span>
          <div className="info-card">
            <span>Key exchange</span>
            <strong>RSA-OAEP · 2048-bit</strong>
          </div>
          <div className="info-card">
            <span>Message encryption</span>
            <strong>AES-256-GCM</strong>
          </div>
          <div className="info-card">
            <span>RSA Key ID</span>
            <strong>{session?.rsaId ?? "—"}</strong>
          </div>
        </div>

        <div className="sidebar-section">
          <span className="section-label">ACTIVE SESSION</span>
          <div className="session-id">
            {session?.sessionId ?? "No active session"}
          </div>
        </div>

        <button
          className="connect-button"
          onClick={connect}
          disabled={busy}
        >
          {status === "connected" ? "↻ New session" : "🔒 Connect"}
        </button>

        <p className="sidebar-footer">
          Educational encrypted communication demo.
          Not a replacement for TLS.
        </p>
      </aside>

      <main className="main">
        <header className="chat-header">
          <div>
            <h1>Encrypted Communication</h1>
            <p>Secure client-server messaging</p>
          </div>
          <span className="header-badge">RSA + AES</span>
        </header>

        <div className="chat-area">
          {messages.length === 0 && (
            <div className="empty-state">
              <div className="empty-icon">🔐</div>
              <h2>Welcome to SecureChat</h2>
              <p>
                Establish an encrypted session to start
                exchanging messages with the server.
              </p>
              <button
                onClick={connect}
                disabled={busy}
                className="primary-button"
              >
                {status === "connecting"
                  ? "Connecting..."
                  : "Establish Secure Connection"}
              </button>
            </div>
          )}

          {messages.map((message) => (
            <div
              key={message.id}
              className={`message ${message.type}`}
            >
              <div className="message-label">
                {message.type === "user" ? "YOU" : "SECURE SERVER"}
              </div>
              <div className="message-bubble">
                <div className="message-text">{message.text}</div>
                {showEncrypted && (
                  <div className="encrypted-preview">
                    <span>ENCRYPTED PAYLOAD</span>
                    <code>{message.encrypted}</code>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        <div className="chat-bottom">
          {error && <div className="error-message">⚠ {error}</div>}

          <label className="display-option">
            <input
              type="checkbox"
              checked={showEncrypted}
              onChange={(e) => setShowEncrypted(e.target.checked)}
            />
            Show encrypted data
          </label>

          <form className="message-form" onSubmit={handleSend}>
            <input
              type="text"
              placeholder={
                session
                  ? "Type your secure message..."
                  : "Connect to start messaging..."
              }
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={!session || busy}
            />
            <button type="submit" disabled={!session || busy || !input.trim()}>
              {busy ? "Sending..." : "Send →"}
            </button>
          </form>

          <div className="security-note">
            🔒 Messages are encrypted in the browser before transmission.
          </div>
        </div>
      </main>
    </div>
  );
}
