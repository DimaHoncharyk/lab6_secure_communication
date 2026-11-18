import React, { useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import keycloak from "./keycloak";
import "./index.css";

let initializationPromise = null;

function initializeKeycloak() {
  if (!initializationPromise) {
    initializationPromise = keycloak.init({
      onLoad: "check-sso",
      pkceMethod: "S256",
      checkLoginIframe: false
    });
  }
  return initializationPromise;
}

function AuthGate() {
  const [loading, setLoading] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    initializeKeycloak()
      .then((isAuthenticated) => {
        setAuthenticated(isAuthenticated);
      })
      .catch((err) => {
        console.error(err);
        setError("Keycloak initialization failed");
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="auth-page">
        <h2>Connecting to Keycloak...</h2>
      </div>
    );
  }

  if (error) {
    return (
      <div className="auth-page">
        <h2>{error}</h2>
        <p>Check that Keycloak is running on port 8081.</p>
      </div>
    );
  }

  if (!authenticated) {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <div className="auth-logo">◆</div>
          <h1>SecureChat</h1>
          <p>Secure Communication · Laboratory №8</p>

          <div className="auth-buttons">
            <button onClick={() => keycloak.login({
              redirectUri: window.location.origin + "/"
            })}>
              Увійти
            </button>

            <button
              className="register-button"
              onClick={() => keycloak.register({
                redirectUri: window.location.origin + "/"
              })}
            >
              Зареєструватися
            </button>
          </div>

          <span className="auth-caption">
            Authentication via OpenID Connect + PKCE S256
          </span>
        </div>
      </div>
    );
  }

  return <App keycloak={keycloak} />;
}

ReactDOM.createRoot(
  document.getElementById("root")
).render(
  <React.StrictMode>
    <AuthGate />
  </React.StrictMode>
);
