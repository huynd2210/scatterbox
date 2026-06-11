// Entry point: mount the app. All state lives in the daemon; the UI is a
// thin live view over its HTTP API + WebSocket feed.
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
