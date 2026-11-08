// Package approval implements the approval workflow for writes (phase 2):
// approval requests, multi-step approval with step-up authentication,
// rejection, cancellation, expiry, asynchronous execution of approved
// writes, and break-glass elevation.
//
// # Wiring
//
// The gateway submits writes; the service executes them through the
// gateway. To avoid an import cycle the gateway defines the small
// gateway.Approvals interface, which *Service implements:
//
//	gw, _ := gateway.New(gateway.Options{...})
//	svc := approval.New(approval.Options{Config: cfg, Store: st, Executor: gw, Audit: auditLog, Events: pub})
//	gw.SetApprovals(svc)
//	go svc.Run(ctx) // expiry, stale-run recovery, resume approved requests
//
// Every entry point (MCP, connectRPC, web console) submits writes by
// calling gateway.ExecuteSQL, which returns status "pending" with the
// request ID. The web UI, Slack and the connect API then use the methods
// below.
//
// # API
//
//   - Submit: called by the gateway (through SubmitWrite) for a write the
//     policy marked approve. Stores the request with the approval rule's
//     steps frozen, the planner estimate, the affected-rows limit and a
//     binding hash over (database, raw SQL, requester, approval rule,
//     config version). Emits approval_requested.
//   - Get: one request, visible only to its requester (the human and
//     their agents) and to eligible approvers; everyone else gets
//     ErrNotFound, exactly as for a nonexistent ID.
//   - List: ScopeMine (requested by me or my agents), ScopeAwaitingMe
//     (pending, and I can approve the current step), ScopeDecided (no
//     longer pending, visible to me). Lists carry the normalized SQL only.
//   - Approvers: known users (store users table plus people named in the
//     configuration) eligible for the next step.
//   - Approve: humans only, with a step-up (passkey or IdP
//     re-authentication) no older than approvals.step_up_max_age. The
//     requester (for agent requests, the human the agent acts for) can
//     never approve; one person approves at most one step; the approver
//     must hold the step's role on the database or belong to its group.
//     After the last step the request becomes approved and is executed
//     asynchronously.
//   - Reject: humans eligible for any step, with an optional comment (no
//     step-up, so that Slack can offer a reject button).
//   - Cancel: the requester (or their agents) withdraws a pending request.
//   - Elevate / ElevationActive / ActiveGrants: break-glass. Humans with
//     the approver role on every requested database (selected by
//     break_glass.databases), with a reason and a fresh step-up, for at
//     most break_glass.max_duration. While active, the gateway executes
//     that human's approve-decision writes immediately (parse-stage and
//     policy denials and the affected-rows limit still apply). Emits
//     break_glass_used.
//   - Run: background loop (expire pending requests, fail stale running
//     requests, start approved requests that are not running).
//
// # Execution
//
// Exactly one worker executes an approved request: the status moves
// approved → running with a conditional update, which also makes the
// approval single-use. Before executing, the binding hash is verified, an
// audit entry is written (no audit, no write), and the gateway
// re-evaluates the requester's role (writer) and the policy with the
// current configuration; if the decision is no longer approve under the
// same approval rule the request fails ("not executed because the decision has changed").
// The write runs in a read-write transaction and is rolled back if it
// affects more rows than the limit shown to approvers. RETURNING rows are
// masked like read results for the requester and stored with the result.
// A request found running for longer than any statement could take (a
// crash mid-execution) is marked failed with an unknown outcome; it is
// never re-run.
//
// Every state change is written to the audit log (event "approval") and
// published as an event. Events never contain literals, raw SQL or result
// values.
package approval
