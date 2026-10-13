---
name: review-ticket
description: "Audit an implementation PR as the strong tier: check whether the code faithfully implements the originating ticket and spec (missing requirements, scope creep, wrong implementation, and anchor compliance), and either request changes (needs-fix) or approve and merge to main."
disable-model-invocation: true
---

# Review Ticket

Audit an implementation PR as the strong tier.

Every implementation PR targets `main`, links its ticket with `Closes #<n>`, and is labelled `needs-review` and `model:strong`. Read [ticket-workflow.md](../../../docs/agents/ticket-workflow.md) and [issue-tracker.md](../../../docs/agents/issue-tracker.md) first.

## Review division

Routine code review belongs to `/implement`: the weak tier is responsible for code cleanliness, conventions, Fowler smells, test suites, and running `code-review`. Do NOT re-run `code-review` or review code details here.

The strong tier's job is strictly to check whether the implementation faithfully implements the originating ticket and spec, or drifts from its goal.

## Process

### 1. Load the PR and ticket

Fetch the PR and its context:

```bash
gh pr view <pr-number> --comments
gh pr diff <pr-number> --stat
```

From the PR body:
- Note the ticket number from `Closes #<n>`.
- Fetch the ticket and parent spec: `gh issue view <ticket-number> --comments`.
- Note the verification commands the PR ran and the drift check comment left by the implementer.

### 2. Audit against the ticket and spec

Audit the diff against the originating ticket and spec (`gh pr diff <pr-number>`). Report:

- **Missing or partial requirements**: requirements the ticket or spec asked for that are missing or partial.
- **Scope creep / goal drift**: behaviour in the diff that wasn't asked for, or where the implementation drifts from what the ticket requested (`## What to build`).
- **Wrong implementation**: requirements that look implemented but where the implementation looks wrong.
- **Acceptance criteria**: whether every criterion in `## Acceptance criteria` holds and was demonstrated by the verification commands.
- **Anchors & boundaries**: whether public interface changes match the ticket's `## Implementation plan` and `## Anchors`, without uncoordinated public interface breaks for sibling tickets.
- **Drift verification**: inspect the implementer's drift check comment to ensure sibling tickets were not broken.

Do not review code formatting, style, or local refactoring: routine review was resolved by `/implement`.

### 3. Act on findings

#### Option A: Request changes (needs-fix)

If requirements are missing, behaviour drifted, or anchors broke:

1. Submit actionable feedback on GitHub citing the ticket or spec and explaining the deviation:
   ```bash
   gh pr review <pr-number> --request-changes --body "<actionable feedback on goal or spec deviation>"
   ```
2. Swap labels on the PR:
   ```bash
   gh pr edit <pr-number> --remove-label "needs-review" --remove-label "model:strong" --add-label "needs-fix" --add-label "model:weak"
   ```
3. If the deviation revealed that subsequent tickets' plans need architectural adjustment beyond this PR, open a `needs-replan` escalation ticket blocking the affected tickets.

The PR is now ready for a weak-tier session to fix via `/implement`.

#### Option B: Approve and merge

If the code faithfully implements the ticket and spec, acceptance criteria hold, anchors are preserved, and tests pass:

1. Submit approval on GitHub:
   ```bash
   gh pr review <pr-number> --approve --body "<summary of approval>"
   ```
2. Merge the PR into `main`:
   ```bash
   gh pr merge <pr-number> --squash --delete-branch
   ```
   Merging to `main` automatically closes the ticket linked via `Closes #<n>`.

3. Closing the ticket automatically unblocks any dependent tickets whose blockers are now all resolved, updating the frontier.

