---
name: implement
description: "Implement a piece of work based on a spec or set of tickets."
disable-model-invocation: true
---

Implement the work described by the user in the spec or tickets.

This is weak-tier work (`model:weak`). Read [ticket-workflow.md](../../../docs/agents/ticket-workflow.md) first: it defines the ticket shape, anchors, the drift check, and escalation.

If the user passes a ticket reference, fetch it from the issue tracker and state its title before starting. If the reference is ambiguous, ask. Confirm it is ready: labelled `model:weak`, no open blocker.

If the PR is labelled `needs-fix`, jump to _Fixing a reviewed PR_.

## Implementing a ticket

### 1. Verify the anchors

Check each anchor of this ticket against the current `main`. A broken anchor means the plan can't be trusted: raise a `needs-replan` escalation for this ticket and stop.

### 2. Build it

Create a branch from `main`. Follow the Implementation plan step by step. Call the Skill tool with "tdd" where possible, at pre-agreed seams.

Run typechecking regularly, single test files regularly, and the full test suite once at the end. Build with the commands in `AGENTS.md`.

Escalate with `needs-strong`, after pushing your WIP branch, when:
- a plan step can't be carried out as written, or
- the same verification stays red after 3 attempts.

Departing from the plan is the strong tier's call: escalate rather than redesign.

Done when every plan step is done, every acceptance criterion holds, and the full build and the testcases the plan names pass.

### 3. Review the work

Once done, call the Skill tool with "code-review" to review the work (fixed point `main`).

Fix every hard violation, coding convention issue, and spec finding. Routine code quality is resolved here; the strong tier audits goal and spec alignment, not code details.

### 4. Open the PR

Push and open a PR to `main`:
- Body starts with `Closes #<n>`, then what changed per plan step, and the verification you ran with its result.
- Labels: `needs-review`, `model:strong`.

### 5. Drift check

Run the drift check from ticket-workflow.md against this PR's branch, raise a `needs-replan` escalation if anchors broke, and post the result as a PR comment.

Done when the PR comment lists every open sibling ticket checked. Report the PR, the drift result, and that the PR now waits for `/review-ticket`.

## Fixing a reviewed PR

1. Fetch the PR, its review comments, and its ticket.
2. Check out the PR branch and address requested changes, calling the Skill tool with "tdd" for behaviour changes. A requested change that contradicts the ticket's plan or parent spec is a `needs-strong` escalation, not a fix.
3. Run the full test suite once at the end, re-run "code-review", verification commands, and the drift check.
4. Push, and reply to each review comment with what changed.
5. Swap labels: remove `needs-fix` and `model:weak`, add `needs-review` and `model:strong`.
