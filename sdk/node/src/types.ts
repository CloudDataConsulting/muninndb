/** Configuration for the MuninnDB client. */
export interface MuninnClientOptions {
  /** Base URL of the MuninnDB server. @default "http://localhost:8476" */
  baseUrl?: string;
  /** Bearer token for authentication. */
  token: string;
  /** Request timeout in milliseconds. @default 30_000 */
  timeout?: number;
  /** Maximum number of retry attempts for transient failures. @default 3 */
  maxRetries?: number;
  /** Base delay in milliseconds for exponential backoff. @default 500 */
  retryBackoff?: number;
  /** Default vault to use when none is specified. @default "default" */
  defaultVault?: string;
}

// ---------------------------------------------------------------------------
// Engram
// ---------------------------------------------------------------------------

export interface Engram {
  id: string;
  vault: string;
  concept: string;
  content: string;
  tags: string[];
  confidence: number;
  stability: number;
  memory_type: string;
  type_label: string;
  summary: string;
  entities: string[];
  relationships: string[];
  state: string;
  created_at: string;
  updated_at: string;
  deleted_at?: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

export interface WriteOptions {
  vault?: string;
  concept: string;
  content: string;
  tags?: string[];
  confidence?: number;
  stability?: number;
  memory_type?: string;
  type_label?: string;
  summary?: string;
  entities?: string[];
  relationships?: string[];
}

export interface WriteResponse {
  id: string;
  created_at: string;
}

export interface BatchWriteResult {
  index: number;
  id: string;
  status: string;
  error?: string;
}

export interface BatchWriteResponse {
  results: BatchWriteResult[];
}

// ---------------------------------------------------------------------------
// Activate (semantic recall)
// ---------------------------------------------------------------------------

export interface ActivateOptions {
  vault?: string;
  context: string[];
  threshold?: number;
  limit?: number;
  max_hops?: number;
  profile?: string;
  mode?: string;
  since?: string;
  before?: string;
  include_why?: boolean;
  brief_mode?: boolean;
}

export interface ActivationItem {
  id: string;
  concept: string;
  content: string;
  score: number;
  tags: string[];
  memory_type: string;
  why?: string;
  [key: string]: unknown;
}

export interface BriefSentence {
  id: string;
  text: string;
}

export interface ActivateResponse {
  query_id: string;
  total_found: number;
  activations: ActivationItem[];
  latency_ms: number;
  brief?: BriefSentence[];
}

// ---------------------------------------------------------------------------
// Link (association)
// ---------------------------------------------------------------------------

export interface LinkOptions {
  vault?: string;
  source_id: string;
  target_id: string;
  rel_type: string;
  weight?: number;
}

export interface AssociationItem {
  source_id: string;
  target_id: string;
  rel_type: string;
  weight: number;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Evolve
// ---------------------------------------------------------------------------

export interface EvolveResponse {
  id: string;
}

// ---------------------------------------------------------------------------
// Consolidate
// ---------------------------------------------------------------------------

export interface ConsolidateOptions {
  vault?: string;
  ids: string[];
  merged_content: string;
}

export interface ConsolidateResponse {
  id: string;
  archived: string[];
  warnings: string[];
}

// ---------------------------------------------------------------------------
// Decide
// ---------------------------------------------------------------------------

export interface DecideOptions {
  vault?: string;
  decision: string;
  rationale: string;
  alternatives?: string[];
  evidence_ids?: string[];
}

export interface DecideResponse {
  id: string;
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

export interface RestoreResponse {
  id: string;
  concept: string;
  restored: boolean;
  state: string;
}

// ---------------------------------------------------------------------------
// Traverse
// ---------------------------------------------------------------------------

export interface TraverseOptions {
  vault?: string;
  start_id: string;
  max_hops?: number;
  max_nodes?: number;
  rel_types?: string[];
}

export interface TraversalNode {
  id: string;
  concept: string;
  depth: number;
  [key: string]: unknown;
}

export interface TraversalEdge {
  source: string;
  target: string;
  rel_type: string;
  weight: number;
  [key: string]: unknown;
}

export interface TraverseResponse {
  nodes: TraversalNode[];
  edges: TraversalEdge[];
  total_reachable: number;
  query_ms: number;
}

// ---------------------------------------------------------------------------
// Explain
// ---------------------------------------------------------------------------

export interface ExplainOptions {
  vault?: string;
  engram_id: string;
  query: string[];
}

export interface ExplainComponents {
  semantic: number;
  recency: number;
  confidence: number;
  stability: number;
  association: number;
  [key: string]: unknown;
}

export interface ExplainResponse {
  engram_id: string;
  concept: string;
  final_score: number;
  components: ExplainComponents;
  fts_matches: string[];
  assoc_path: string[];
  would_return: boolean;
  threshold: number;
}

// ---------------------------------------------------------------------------
// State management
// ---------------------------------------------------------------------------

export interface SetStateResponse {
  id: string;
  state: string;
  previous_state: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Deleted / soft-delete list
// ---------------------------------------------------------------------------

export interface DeletedEngram {
  id: string;
  concept: string;
  deleted_at: string;
  [key: string]: unknown;
}

export interface ListDeletedResponse {
  deleted: DeletedEngram[];
  count: number;
}

// ---------------------------------------------------------------------------
// Retry enrichment
// ---------------------------------------------------------------------------

export interface RetryEnrichResponse {
  engram_id: string;
  plugins_queued: string[];
  already_complete: string[];
  note: string;
}

// ---------------------------------------------------------------------------
// Contradictions
// ---------------------------------------------------------------------------

export interface ContradictionItem {
  id_a: string;
  id_b: string;
  concept: string;
  description: string;
  [key: string]: unknown;
}

export interface ContradictionsResponse {
  contradictions: ContradictionItem[];
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

export interface CoherenceResult {
  score: number;
  orphan_ratio?: number;
  contradiction_density?: number;
  duplication_pressure?: number;
  temporal_variance?: number;
  total_engrams?: number;
  /** Legacy coherence fields returned by older servers. */
  issues: string[];
  contradictions?: number;
  [key: string]: unknown;
}

export type StatsScope = "vault" | "global" | "unknown";

export interface StatsResponse {
  engram_count: number;
  vault_count: number;
  index_size: number;
  storage_bytes: number;
  stats_scope: StatsScope;
  storage_bytes_available: boolean;
  index_size_available: boolean;
  /** Legacy single-coherence view retained for source compatibility. */
  coherence?: CoherenceResult;
  /** Current global/admin coherence map; omitted for vault-scoped stats. */
  coherence_by_vault?: Record<string, CoherenceResult>;
  /** Legacy aliases retained for source and runtime compatibility. */
  total_engrams: number;
  total_vaults?: number | null;
  total_links?: number;
  active_engrams?: number;
  deleted_engrams?: number;
  vault: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// List engrams
// ---------------------------------------------------------------------------

export interface ListEngramsResponse {
  engrams: Engram[];
  total: number;
  limit: number;
  offset: number;
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

export interface SessionEntry {
  id: string;
  action: string;
  timestamp: string;
  [key: string]: unknown;
}

export interface SessionResponse {
  entries: SessionEntry[];
  total: number;
  limit: number;
  offset: number;
}

// ---------------------------------------------------------------------------
// Vaults
// ---------------------------------------------------------------------------

export interface VaultsResponse {
  vaults: string[];
}

// ---------------------------------------------------------------------------
// Guide
// ---------------------------------------------------------------------------

export interface GuideResponse {
  guide: string;
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

export interface HealthResponse {
  status: string;
  version: string;
  uptime_seconds: number;
  db_writable: boolean;
}

// ---------------------------------------------------------------------------
// SSE
// ---------------------------------------------------------------------------

export interface SseEvent {
  event?: string;
  data: Record<string, unknown>;
  id?: string;
  retry?: number;
}
