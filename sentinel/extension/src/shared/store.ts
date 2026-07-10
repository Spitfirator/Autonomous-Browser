import { create } from 'zustand';
import type {
  ApprovalRequest,
  ControlRequest,
  ConversationTurn,
  SentinelConfig,
  SentinelEvent,
  Snapshot,
  Status,
} from './types';

export type WsState = 'connecting' | 'connected' | 'offline';

const FEED_CAP = 200;

interface SentinelStore {
  wsState: WsState;
  status: Status | null;
  config: SentinelConfig | null;
  events: SentinelEvent[]; // newest last; render reversed
  approvals: ApprovalRequest[];
  handovers: ControlRequest[];
  lastError: string | null;
  conversationId: string | null; // chat this panel is showing
  turns: ConversationTurn[]; // persisted transcript, rendered before live events

  setWsState: (s: WsState) => void;
  applySnapshot: (snap: Snapshot) => void;
  applyEvent: (event: SentinelEvent) => void;
  setConversation: (id: string | null, turns: ConversationTurn[]) => void;
  reconcileConversation: (id: string | null, turns: ConversationTurn[]) => void;
  setConfig: (config: SentinelConfig) => void;
  setLastError: (message: string | null) => void;
  removeApproval: (approvalId: string) => void;
  removeHandover: (handoverId: string) => void;
}

export const useStore = create<SentinelStore>((set, get) => ({
  wsState: 'connecting',
  status: null,
  config: null,
  events: [],
  approvals: [],
  handovers: [],
  lastError: null,
  conversationId: null,
  turns: [],

  setWsState: (wsState) => set({ wsState }),

  applySnapshot: (snap) =>
    set({
      status: snap.status,
      config: snap.config,
      events: snap.events.slice(-FEED_CAP),
      approvals: snap.pending_approvals,
      handovers: snap.pending_handovers ?? [],
      // conversationId/turns stay: the panel reconciles them against
      // status.conversation_id and refetches turns when they differ.
    }),

  applyEvent: (event) => {
    const state = get();
    const patch: Partial<SentinelStore> = {
      events: [...state.events.slice(-(FEED_CAP - 1)), event],
    };

    switch (event.type) {
      case 'status_changed':
        if (state.status) {
          patch.status = {
            ...state.status,
            agent_status: event.agent_status,
            browser_status: event.browser_status,
            extension_seen: event.extension_seen,
            task: event.task,
            model: event.model,
          };
        }
        if (event.agent_status === 'idle') {
          patch.approvals = [];
          patch.handovers = [];
        }
        break;
      case 'control_request':
        patch.handovers = [...state.handovers, event];
        break;
      case 'control_returned':
        patch.handovers = state.handovers.filter((h) => h.handover_id !== event.handover_id);
        break;
      case 'llm_call':
        if (state.status) {
          patch.status = {
            ...state.status,
            calls_used: event.calls_used,
            calls_budget: event.calls_budget,
            ...(event.total_tokens
              ? { total_tokens: state.status.total_tokens + event.total_tokens }
              : {}),
          };
        }
        break;
      case 'token_usage':
        if (state.status) {
          patch.status = { ...state.status, total_tokens: event.total_tokens };
        }
        break;
      case 'task_started':
        if (state.status) {
          patch.status = { ...state.status, task: event.task, total_tokens: 0, calls_used: 0 };
        }
        break;
      case 'approval_request':
        patch.approvals = [...state.approvals, event];
        break;
      case 'approval_resolved':
        patch.approvals = state.approvals.filter((a) => a.approval_id !== event.approval_id);
        break;
      case 'config_changed':
        patch.config = event.config;
        break;
    }
    set(patch);
  },

  // Explicit switch: fresh chat view.
  setConversation: (conversationId, turns) =>
    set({ conversationId, turns, events: [], approvals: [], handovers: [] }),
  // Reconnect/cross-client sync: adopt the server's chat but keep the live
  // event replay (ChatThread hides turns whose run is already in the feed).
  reconcileConversation: (conversationId, turns) => set({ conversationId, turns }),
  setConfig: (config) => set({ config }),
  setLastError: (lastError) => set({ lastError }),
  removeApproval: (approvalId) =>
    set({ approvals: get().approvals.filter((a) => a.approval_id !== approvalId) }),
  removeHandover: (handoverId) =>
    set({ handovers: get().handovers.filter((h) => h.handover_id !== handoverId) }),
}));
