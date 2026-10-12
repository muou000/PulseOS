---
name: implement
description: "Implement a ticket (or fix a reviewed PR) as the weak tier: follow its plan test-first, open a PR to main, run the drift check, escalate what the plan can't carry."
disable-model-invocation: true
---

Implement the work the user points at. Three entry points:

- **A ticket** (`#<n>`): the main path below.
- **A PR labelled `needs-fix`**: jump to _Fixing a reviewed PR_.
- **No ticket** (work agreed in this conversation, small enough for one session): call the Skill tool with `tdd` at pre-agreed seams, run the full test suite at the end, then call `code-review` and commit to the current branch. The rest of this skill doesn't apply.

For tickets and PRs, read [ticket-workflow.md](../../../docs/agents/ticket-workflow.md) first: it defines the ticket shape, the drift check, and the escalation tickets this skill raises. Everything you know about the work comes from the tracker; fetch it, don't assume.

## Implementing a ticket

### 1. Load the ticket

Fetch the ticket with its comments, its parent spec, and the PRs of its closed blockers. State its title. If the reference is ambiguous, ask.

Confirm it is ready: labelled `model:weak`, no open blocker. If not, stop and say why.

### 2. Verify the anchors

Check each anchor of this ticket against the current `main`. A broken anchor means the plan can't be trusted: raise a `needs-replan` escalation for this ticket and stop.

### 3. Build it

Create a branch from `main`. Follow the Implementation plan step by step, driving each step with the Skill tool `tdd`, and run that step's verification before moving on. Build with the commands in `AGENTS.md`.

Escalate with `needs-strong`, after pushing your WIP branch, when:

- a plan step can't be carried out as written, or
- the same verification stays red after 3 attempts.

Departing from the plan is the strong tier's call: escalate rather than redesign.

Done when every plan step is done, every acceptance criterion holds, and the full build and the testcases the plan names pass.

### 4. Self-review

Call the Skill tool with `code-review`, fixed point `main`. Fix every hard violation and every spec finding; note judgement calls you leave for the reviewer.

### 5. Open the PR

Push and open a PR to `main`:

- Body starts with `Closes #<n>`, then what changed per plan step, and the verification you ran with its result.
- Labels: `needs-review`, `model:strong`.

### 6. Drift check

Run the drift check from ticket-workflow.md against this PR's branch, raise a `needs-replan` escalation if anchors broke, and post the result as a PR comment.

Done when the PR comment lists every open sibling ticket checked. Report the PR, the drift result, and that the PR now waits for `/review-ticket`.

## Fixing a reviewed PR

1. Fetch the PR, its review comments, and its ticket.
2. Check out the PR branch and address every requested change, driving behaviour changes with `tdd`. A requested change that contradicts the ticket's plan is a `needs-strong` escalation, not a fix.
3. Re-run the verification and the drift check, push, and reply to each review comment with what changed.
4. Swap labels: remove `needs-fix` and `model:weak`, add `needs-review` and `model:strong`.
