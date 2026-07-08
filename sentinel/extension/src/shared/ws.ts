// Singleton reconnecting WebSocket owned by whichever extension page is open.
// Backoff 0.5s -> 8s with jitter; the server's first frame is always a snapshot.

import { useStore } from './store';
import type { SentinelEvent, Snapshot } from './types';

const WS_URL = 'ws://127.0.0.1:8765/ws';

let socket: WebSocket | null = null;
let attempts = 0;
let started = false;

function delay(): number {
  const base = Math.min(500 * 2 ** attempts, 8000);
  return base + Math.random() * 300;
}

function connect(): void {
  useStore.getState().setWsState(attempts === 0 ? 'connecting' : 'offline');
  socket = new WebSocket(WS_URL);

  socket.onopen = () => {
    attempts = 0;
    useStore.getState().setWsState('connected');
  };

  socket.onmessage = (msg: MessageEvent<string>) => {
    let frame: Snapshot | SentinelEvent | { type: string };
    try {
      frame = JSON.parse(msg.data);
    } catch {
      return;
    }
    if (frame.type === 'snapshot') {
      useStore.getState().applySnapshot(frame as Snapshot);
    } else if (frame.type !== 'pong') {
      useStore.getState().applyEvent(frame as SentinelEvent);
    }
  };

  socket.onclose = () => {
    useStore.getState().setWsState('offline');
    attempts += 1;
    setTimeout(connect, delay());
  };

  socket.onerror = () => socket?.close();
}

export function startWs(): void {
  if (started) return;
  started = true;
  connect();
}
