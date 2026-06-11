import { useEffect, useRef } from "react";
import type { DaemonEvent } from "./types";

/** Subscribe to the daemon's event feed; reconnects quietly if the daemon
 * restarts. The handler is kept in a ref so callers may pass a fresh
 * closure every render without tearing the socket down. */
export function useDaemonEvents(onEvent: (e: DaemonEvent) => void): void {
  const handler = useRef(onEvent);
  handler.current = onEvent;

  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;
    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws`);
      ws.onmessage = (m) => {
        try {
          handler.current(JSON.parse(m.data as string) as DaemonEvent);
        } catch {
          /* malformed frame; ignore */
        }
      };
      ws.onclose = () => {
        if (!closed) setTimeout(connect, 2000);
      };
    };
    connect();
    return () => {
      closed = true;
      ws?.close();
    };
  }, []);
}
