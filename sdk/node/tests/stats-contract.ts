import type { StatsResponse } from "../src/types.js";

// Compile-time compatibility contract for properties required by pre-scoped-
// stats SDK releases. Runtime normalization in MuninnClient.stats fills these
// for both current and legacy wire responses.
export function assertLegacyStatsShape(stats: StatsResponse): void {
  const totalEngrams: number = stats.total_engrams;
  const vault: string = stats.vault;
  const legacyScore: number | undefined = stats.coherence?.score;
  const legacyIssues: string[] | undefined = stats.coherence?.issues;
  const scopedEngrams: number = stats.engram_count;
  const scope: "vault" | "global" | "unknown" = stats.stats_scope;

  void totalEngrams;
  void vault;
  void legacyScore;
  void legacyIssues;
  void scopedEngrams;
  void scope;
}
