# muninndb (CDC fork) — READ THIS FIRST

**Policy: upgrade-only. CDC does not develop in this fork.**

This is a fork of `scrypster/muninndb` kept ONLY to pin/deploy upstream
releases. There is **no standing authorization** for code changes here — not
for bug fixes, not for auth hardening, not for "small" patches. Any change
requires Bernie's explicit, per-instance authorization, given for the specific
change in the current conversation. If you were asked to "fix" something in
MuninnDB, the correct move is: check whether a newer upstream release fixes
it, and otherwise file the finding — do not write code in this repo.

The 2026-07-12 vault-auth sprint (7 draft PRs, 3 worktrees) was unauthorized
work by an agent session missing this context. It was retired on 2026-07-23;
archive tags `archive/2026-07-vault-auth/*` preserve it.

Full policy, current-version facts, and the post-demo evaluation criteria:
`~/repos/cdc/cdc-open-memory/docs/muninndb-upgrade-policy.md`

Operational runbook for the deployed server (mini-i7, launchd):
`~/repos/cdc/cdc-open-memory/docs/muninndb-mini-i7-runbook.md`
