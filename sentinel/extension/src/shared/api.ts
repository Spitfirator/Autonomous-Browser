import type { HistoryRecord, SentinelConfig, Status } from './types';

export const BASE = 'http://127.0.0.1:8765';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
  }
  return body as T;
}

export const api = {
  status: () => request<Status>('/api/status'),
  startTask: (task: string, maxSteps?: number) =>
    request<{ run_id: string }>('/api/task', {
      method: 'POST',
      body: JSON.stringify({ task, ...(maxSteps ? { max_steps: maxSteps } : {}) }),
    }),
  sendMessage: (text: string) =>
    request<{ kind: 'task' | 'followup' | 'steer'; run_id?: string }>('/api/message', {
      method: 'POST',
      body: JSON.stringify({ text }),
    }),
  control: (command: 'pause' | 'resume' | 'stop') =>
    request<{ ok: boolean }>(`/api/agent/${command}`, { method: 'POST' }),
  getConfig: () => request<SentinelConfig>('/api/config'),
  putConfig: (patch: object) =>
    request<SentinelConfig>('/api/config', { method: 'PUT', body: JSON.stringify(patch) }),
  getKeys: () => request<Record<string, boolean>>('/api/keys'),
  putKey: (name: string, value: string) =>
    request<{ ok: boolean }>('/api/keys', { method: 'PUT', body: JSON.stringify({ name, value }) }),
  resolveApproval: (approvalId: string, approve: boolean) =>
    request<{ resolved: boolean }>(`/api/approvals/${approvalId}`, {
      method: 'POST',
      body: JSON.stringify({ approve }),
    }),
  completeHandover: (handoverId: string, note: string) =>
    request<{ resolved: boolean }>(`/api/handover/${handoverId}/complete`, {
      method: 'POST',
      body: JSON.stringify({ note }),
    }),
  history: (limit = 50) => request<HistoryRecord[]>(`/api/history?limit=${limit}`),
  actions: () => request<string[]>('/api/actions'),
};
