# Port plan review with Claude

Agree on [the port plan](../PORT-PLAN.md) before starting Phase A. The review covers upstream `7764928` and Java baseline `966e1db`. The upstream clone is at `../uma4agents`. Read the pinned Git objects because the local checkout may be on a different revision.

## How we work here

1. Read the plan and [Codex findings](CODEX-REVIEW.md). Claude records an independent response in [CLAUDE-REVIEW.md](CLAUDE-REVIEW.md), using the finding IDs. For each finding, record agreement, a proposed change, or a disagreement with its evidence. Add new findings with IDs starting at `CL-1`.
2. Codex replies in [CODEX-REVIEW.md](CODEX-REVIEW.md) under a dated follow-up. Each reviewer maintains their own review file. Use relative links for local files and pin upstream references to a commit, with line numbers where useful.
3. Record outcomes in [DECISIONS.md](DECISIONS.md). Include the agreed wording or action, any tradeoff we accepted, and where the plan was updated. Keep open items visible until both reviewers agree or the user resolves the difference. Update `PORT-PLAN.md` with the resolved decisions and identify the resulting revision by commit or file hash.
4. Each reviewer records their own sign-off against the same plan revision in `DECISIONS.md`. Phase A implementation starts after both sign-offs and at the user's direction. The agreed Phase A spike is implementation work and starts at that point.

Use the folder for handoffs between sessions. The latest open decision and the two sign-off entries should tell the next reviewer where to resume.

## Phase A records

- [PHASE-A-SPIKE.md](PHASE-A-SPIKE.md): the SDK and fallback decision with its evidence, and the reconciliation of the early cherry-picks.
- [PHASE-A-GATES.md](PHASE-A-GATES.md): gate results against the Python reference and the Java port, with logs in [`phase-a-evidence/`](phase-a-evidence/).
- [Independent Phase A sign-off](CODEX-REVIEW.md#independent-phase-a-sign-off) covers the final Java run, the recovery fault injections, and the portal and HTTP shim checks.

## Phase B records

- [PHASE-B-GATES.md](PHASE-B-GATES.md): gate inputs, requirement map and unit evidence.
- [PHASE-B-CODEX-VERIFICATION.md](PHASE-B-CODEX-VERIFICATION.md): the independent live run, with output in [`phase-b-evidence/`](phase-b-evidence/).

## Phase C records

- [PHASE-C-GATES.md](PHASE-C-GATES.md): the store and rotation gates, the requirement map, and the audit of upstream #38, #41 and #43.
- [PHASE-C-CODEX-VERIFICATION.md](PHASE-C-CODEX-VERIFICATION.md): the independent reference controls and Java verification, with output in [`phase-c-evidence/`](phase-c-evidence/).

## Phase D records

- [PHASE-D-GATES.md](PHASE-D-GATES.md): the intent, assurance, consequence, first-party and
  sub-agent gates and the full pinned demo, the requirement map, the vectors, and the
  decisions and findings, with logs in [`phase-d-evidence/`](phase-d-evidence/).

## Phase E records

- [E1 verification](PHASE-E1-CODEX-VERIFICATION.md) covers independently configured
  authority establishment and the separate owner paths.
- [E2 verification](PHASE-E2-CODEX-VERIFICATION.md) covers the organization
  authority, roles, delegated administration and attested clearance.
- [E3 verification](PHASE-E3-CODEX-VERIFICATION.md) covers jointly held
  accounts, signed holder verdicts and enforcement against the published mandate.
- [E4 verification](PHASE-E4-CODEX-VERIFICATION.md) covers Cross App Access,
  workforce enrolment and full-stack smoke.


## Phase F records

- [Integrations and release verification](PHASE-F-CODEX-VERIFICATION.md) records
  the adapter, owner device and CLI, n8n, portals, and staged release checks.
