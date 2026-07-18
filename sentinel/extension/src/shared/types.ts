// TypeScript mirror of server/events.py + REST DTOs. Keep in sync by hand.

export type AgentStatus = 'idle' | 'running' | 'paused' | 'stopping';
export type Verdict =
  | 'allowed'
  | 'approval_reused'
  | 'blocked'
  | 'approval_required'
  | 'denied_by_human'
  | 'denied_timeout'
  | 'handoff_required'
  | 'handoff_returned'
  | 'handoff_timeout'
  | 'shadow_blocked'
  | 'shadow_approval_required'
  | 'shadow_handoff_required';
export type Provider = 'ollama' | 'gemini' | 'groq' | 'openai' | 'anthropic' | 'openrouter';
export type PolicyMode = 'enforce' | 'shadow' | 'off';

interface EventBase {
  ts: number;
  seq: number;
  run_id: string | null;
  conversation_id?: string | null;
}

export interface StatusChanged extends EventBase {
  type: 'status_changed';
  agent_status: AgentStatus;
  browser_status: string;
  extension_seen: boolean;
  task: string | null;
  model: string;
}

export interface TaskStarted extends EventBase {
  type: 'task_started';
  task: string;
  max_steps: number;
  model: string;
  provider: string;
}

export interface StepEvent extends EventBase {
  type: 'step';
  step: number;
  url: string;
  title: string;
  evaluation_previous_goal: string | null;
  next_goal: string | null;
  memory: string | null;
  thinking: string | null;
  actions: { name: string; params: Record<string, unknown> }[];
  screenshot_b64: string | null;
}

export interface LLMCall extends EventBase {
  type: 'llm_call';
  model: string;
  provider: string;
  latency_ms: number;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  total_tokens: number | null;
  calls_used: number;
  calls_budget: number;
  is_fallback: boolean;
}

export interface PromptInjectionDetected extends EventBase {
  type: 'prompt_injection_detected';
  url: string | null;
  score: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  signals: string[];
  content_hash: string;
  action_taken: 'model_warned' | 'shadow_monitored';
}

export interface EnforcementDecision extends EventBase {
  type: 'enforcement_decision';
  action: string;
  params_preview: string;
  url: string | null;
  verdict: Verdict;
  rule: string;
  reason: string;
  mode: PolicyMode;
  decision_ms: number;
  enforcement_ms: number;
  action_id: string | null;
  risk_score: number;
  risk_factors: string[];
  capabilities: string[];
  taint_labels: string[];
  target_origin: string | null;
  params_digest: string | null;
}

export interface ActionAudit extends EventBase {
  type: 'action_audit';
  phase: 'attempted' | 'completed';
  action_id: string;
  action: string;
  url: string | null;
  target_origin: string | null;
  capabilities: string[];
  risk_score: number;
  enforcement_ms: number;
  risk_factors: string[];
  taint_labels: string[];
  params_digest: string;
  verdict: string;
  outcome:
    | 'pending'
    | 'executed'
    | 'tool_error'
    | 'blocked'
    | 'denied'
    | 'timeout'
    | 'handoff_returned'
    | 'handoff_timeout'
    | 'exception';
  duration_ms: number | null;
  error_type: string | null;
}

export interface ApprovalRequest extends EventBase {
  type: 'approval_request';
  approval_id: string;
  action: string;
  params: Record<string, unknown>;
  url: string | null;
  expires_at: number;
  reason: string;
  risk_score: number;
  risk_factors: string[];
  approval_key: string | null;
  can_approve_scope: boolean;
}

export interface ApprovalResolved extends EventBase {
  type: 'approval_resolved';
  approval_id: string;
  approved: boolean;
  resolved_by: 'user' | 'timeout';
  scope: 'once' | 'similar';
}

export interface OperatorMessage extends EventBase {
  type: 'user_message';
  text: string;
  kind: 'task' | 'followup' | 'steer';
}

export interface ActionExecuting extends EventBase {
  type: 'action_executing';
  action: string;
}

export interface ActionDone extends EventBase {
  type: 'action_done';
  action: string;
}

export interface ControlRequest extends EventBase {
  type: 'control_request';
  handover_id: string;
  reason: string;
  url: string | null;
  expires_at: number;
}

export interface ControlReturned extends EventBase {
  type: 'control_returned';
  handover_id: string;
  note: string | null;
  resolved_by: 'user' | 'timeout';
}

export interface TaskDone extends EventBase {
  type: 'task_done';
  success: boolean | null;
  final_result: string | null;
  steps: number;
  duration_s: number;
  usage: Record<string, unknown>;
  enforcement: Record<string, unknown>;
}

export interface TaskError extends EventBase {
  type: 'task_error';
  error: string;
  kind: 'exception' | 'budget_exceeded' | 'stopped';
}

export interface TokenUsage extends EventBase {
  type: 'token_usage';
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  by_model: Record<string, number>;
}

export interface ConfigChanged extends EventBase {
  type: 'config_changed';
  config: SentinelConfig;
}

export type SentinelEvent =
  | StatusChanged
  | TaskStarted
  | StepEvent
  | LLMCall
  | PromptInjectionDetected
  | EnforcementDecision
  | ActionAudit
  | ApprovalRequest
  | ApprovalResolved
  | OperatorMessage
  | ActionExecuting
  | ActionDone
  | ControlRequest
  | ControlReturned
  | TaskDone
  | TaskError
  | TokenUsage
  | ConfigChanged;

export interface Snapshot {
  type: 'snapshot';
  ts: number;
  seq: number;
  conversation_id?: string | null;
  status: Status;
  events: SentinelEvent[];
  pending_approvals: ApprovalRequest[];
  pending_handovers: ControlRequest[];
  config: SentinelConfig;
}

// ── REST DTOs ────────────────────────────────────────────────────────────────
export interface Status {
  backend: string;
  agent_status: AgentStatus;
  browser_status: string;
  extension_seen: boolean;
  task: string | null;
  run_id: string | null;
  model: string;
  provider: string;
  calls_used: number;
  calls_budget: number;
  total_tokens: number;
  ws_clients: number;
  conversation_id?: string | null;
}

export interface ThrottleConfig {
  min_interval_s: number;
  backoff_s: number;
  max_retries: number;
}

export interface ModelConfig {
  provider: Provider;
  model: string;
  temperature: number | null;
  throttle: ThrottleConfig | null;
  fallback: ModelConfig | null;
}

export interface Budgets {
  max_steps: number;
  max_llm_calls: number;
  approval_timeout_s: number;
  handover_timeout_s: number;
}

export interface PromptInjectionPolicy {
  enabled: boolean;
  detection_threshold: number;
  block_threshold: number;
}

export interface DataFlowPolicy {
  enabled: boolean;
  trusted_domains: string[];
  sensitive_data_verdict: 'block' | 'approve';
}

export interface AdaptiveApprovalPolicy {
  enabled: boolean;
  approval_risk_threshold: number;
  grant_ttl_s: number;
  grant_max_uses: number;
  max_prompts_per_run: number;
  fatigue_strategy: 'handoff' | 'block';
}

export interface AuditPolicy {
  store_screenshots: boolean;
  store_model_reasoning: boolean;
}

export interface Policies {
  mode: PolicyMode;
  domain_allowlist: string[] | null;
  domain_blocklist: string[];
  blocked_actions: string[];
  approval_required_actions: string[];
  approval_required_domains: string[];
  sensitive_domains: string[];
  prompt_injection: PromptInjectionPolicy;
  data_flow: DataFlowPolicy;
  adaptive_approvals: AdaptiveApprovalPolicy;
  audit: AuditPolicy;
  budgets: Budgets;
}

export interface SentinelConfig {
  model: ModelConfig;
  policies: Policies;
  use_judge: boolean;
  pinned_extension_id: string | null;
}

export interface EnforcementSummary {
  decisions: Partial<Record<Verdict, number>>;
  decision_count: number;
  decision_ms_total: number;
  decision_ms_mean: number;
  decision_ms_max: number;
  enforcement_ms_total?: number;
  enforcement_ms_mean?: number;
  enforcement_ms_max?: number;
  human_wait_s: number; // total frozen-on-a-human time (approvals + handoffs)
  approval_wait_s?: number; // approval gates — the extra time enforcement adds
  handoff_wait_s?: number; // handed-over steps (login/CAPTCHA) — baseline, happens either way
  human_interventions: number;
  prompt_injection_detections?: number;
  approval_prompts?: number;
  approval_reuses?: number;
  actions_attempted?: number;
  actions_completed?: number;
}

// One non-allow enforcement decision from a run's trace, for the Activity tab's
// "could you tell why?" list. `understood` is the operator's tick (null = unset).
export interface DecisionRow {
  seq: number;
  ts: number;
  action: string;
  url: string | null;
  verdict: Verdict;
  rule: string;
  reason: string;
  understood: boolean | null;
}

export interface HistoryRecord {
  run_id: string;
  task: string;
  started_at: number;
  duration_s?: number;
  status?: string;
  success?: boolean;
  steps?: number;
  llm_calls?: number;
  total_tokens?: number;
  by_model?: Record<string, number>;
  final_result?: string;
  error?: string;
  model?: string;
  provider?: string;
  policy_mode?: PolicyMode;
  enforcement?: EnforcementSummary;
  conversation_id?: string | null;
}

// Full event trace of one run, served from data/traces/<run_id>/events.jsonl.
// When truncated, `events` holds the LAST `limit` of `total` events.
export interface TraceEventsResponse {
  run_id: string;
  total: number;
  truncated: boolean;
  events: SentinelEvent[];
}

export interface ConversationMeta {
  conversation_id: string;
  title: string;
  created_at: number;
  updated_at: number;
  turn_count: number;
  preview: string;
  active: boolean;
}

export interface ConversationTurn {
  role: 'user' | 'agent';
  text: string;
  ts: number;
  run_id: string | null;
  kind: 'task' | 'followup' | 'steer' | 'result' | 'error';
}

export interface ConversationDetail {
  conversation_id: string;
  title: string;
  created_at: number;
  updated_at: number;
  turns: ConversationTurn[];
}
