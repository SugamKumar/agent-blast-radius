# Threat model

This threat model is about identity and access. How an agent comes to be
compromised (for example through prompt injection) is out of scope; that is
the subject of the separate insider-threat-agent project.

## System

A triage agent summarises the issues in a public tracker for one user. It
reaches tools through two servers, each of which demands an access token:

- **issues**: a public issue tracker. Comments are public.
- **notes**: the user's private notes, including credentials.

An authorization server issues the tokens. A policy gateway can sit between
the agent and the servers.

## Assets

| Asset | Where | Stand-in in the lab |
|---|---|---|
| Ordinary private data | a normal note | `standard_note` canary |
| Highly privileged data | a restricted note needing `notes:admin` | `restricted_note` canary |
| Integrity of public records | the two original issues | closed or deleted state |
| The user's delegated access | tokens held by the agent's tool client | signed JWTs in `lab/tokens.py` |

## Trust boundaries

1. **User to agent.** The user delegates some of their access to the agent.
2. **Agent to servers.** The model decides which tools to call; the token
   decides what those calls can do.
3. **issues server to notes server.** One server calling another on the
   user's behalf.
4. **Agent to public comments.** Anything written here leaves the organisation.

## Key assumption: assume breach

Following zero-trust practice (NIST SP 800-207), the agent is treated as a
workload that may be under an attacker's control at any time. The lab asks:
**given that, what does the agent's access allow?** This is measured with a
scripted compromised agent, so the answer depends only on the authorization
design, not on any particular model's behaviour.

The attacker cannot see or forge tokens and cannot change server
configuration. Tokens are signed JWTs; the tests confirm that tampered,
unsigned, algorithm-confusion and foreign-key tokens are rejected. They can only make the agent issue tool calls. Their goals
are to publish private note contents (confidentiality) and to close or
delete legitimate issues (integrity).

## Threats and controls

| # | Threat | Weakness class | OWASP agentic | Present in | Control that removes it |
|---|---|---|---|---|---|
| T1 | Agent holds scopes its task does not need | CWE-250 Execution with Unnecessary Privileges | ASI03 | `overbroad_scope` | Grant only `issues:read`; do not connect the notes server |
| T2 | Agent uses a personal token: every scope, every server, no expiry | CWE-250; CWE-613 Insufficient Session Expiration | ASI03 | `personal_token` | Short-lived tokens bound to one server (audience) with minimal scope |
| T3 | Issue server forwards the caller's token to the notes server, which trusts it | CWE-441 Confused Deputy; CWE-863 Incorrect Authorization | ASI03 | `token_passthrough` | Notes server validates audience and scope on every call; issue server uses token exchange limited by the user's grants |
| T4 | Agent uses a permitted tool to publish private data | CWE-863 | ASI02 | all vulnerable configs | Gateway: task allowlist, approval for public writes, private-to-public data-flow rule |
| T5 | Agent closes or deletes legitimate issues | CWE-863 | ASI02 | all vulnerable configs (delete needs the personal token) | Least-privilege scopes; gateway allowlist; approval for destructive actions |
| T6 | Agent stays inside the task's allowed tools but swaps the target (attaches the credentials note in place of the meeting notes, or closes a different issue) | CWE-863 | ASI02 | any task that legitimately has a write tool | Gateway: per-task resource limits for notes and issues, failing closed on anything undeclared |

In STRIDE terms: T1 to T3 are elevation of privilege, T4 and T6 are
information disclosure, T5 is tampering.

## Why an instruction to the model is not an access control

Telling the model how to behave does nothing once the agent is under an
attacker's control. `prompt_defense_only` has the same blast radius as
`overbroad_scope`. Access control has to be enforced outside the model.

## Residual risk after hardening

- The data-flow rule depends on tools being labelled correctly. Its first
  version watched only for read-then-write at the agent, so it missed
  `attach_note`, which copies private data inside one server-side call. The
  tool is now labelled as a private-to-public flow. A new unlabelled tool of
  that kind would be missed again.
- The data-flow rule does not address tampering: closing an issue moves no data.
- A compromised agent that misuses a permitted tool on a permitted resource
  (a misleading comment, say) is neither blocked nor detected. Measured in
  `lab/evasion.py`: it does harm in 9 of 12 sessions with no alert. Access
  control cannot judge content.
- Resource limits only help if someone declares the task's resources. The
  lab now fails closed when they are missing; the first version failed open
  and let a disguised leak through.
- The secret-pattern rule (R6) is easy to evade by encoding the secret.
- A human approver can be talked into approving a harmful request.
- The hardened configuration supports only the task it was built for. Each
  additional job needs its own narrow grant.

## Detection coverage

| Rule | Detects | Threat |
|---|---|---|
| R1 | Private read followed by a public write in one session | T4 |
| R2 | Tool call outside the task allowlist | T1, T4, T5 |
| R3 | Agent using a wildcard or non-expiring token | T2 |
| R4 | Server-to-server call with a token minted for another audience | T3 |
| R5 | Three or more denied calls in one session | probing after compromise |
| R6 | Secret-shaped value in the arguments of a public write | T4 |
| R7 | Destructive tool ran outside the task allowlist | T5 |
| R8 | Non-read tool pointed at a resource the task does not declare | T6 |

R3 and R4 describe the configuration, so they also fire on normal sessions.
They are reported as findings and not counted as attack detections.
