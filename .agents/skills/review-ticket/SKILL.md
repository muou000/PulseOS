---
name: review-ticket
description: "Review a PR as the strong tier: run two-axis code review (Standards + Spec), check plan compliance, and either request changes (needs-fix) or approve and merge to main."
disable-model-invocation: true
---

# Review Ticket

Review an implementation PR as the strong tier.

Every implementation PR targets `main`, links its ticket with `Closes #<n>`, and is labelled `needs-review` and `model:strong`. Read [ticket-workflow.md](../../../docs/agents/ticket-workflow.md) and [issue-tracker.md](../../../docs/agents/issue-tracker.md) first.

## Process

### 1. Load the PR and ticket

Fetch the PR and its metadata:

```bash
gh pr view <pr-number> --comments
gh pr diff <pr-number>
```

From the PR body:
- Note the ticket number from `Closes #<n>`.
- Fetch the ticket and parent spec: `gh issue view <ticket-number> --comments`.
- Note the verification commands the PR ran and the drift check comment left by the implementer.

### 2. Conduct the review

1. **Two-axis review**:
   Call the Skill tool with `code-review`, fixed point `main`. This evaluates Standards (repo conventions + Fowler smells) and Spec (faithful implementation of the originating ticket and spec).

2. **Plan and Anchor compliance**:
   - Check that the PR changes match the symbols and modules named in the ticket's `## Implementation plan`.
   - Verify that stated `## Anchors` were preserved or satisfied as designed.
   - Confirm that the PR does not introduce uncoordinated public interface breaks for sibling tickets.

3. **Drift verification**:
   Inspect the implementer's drift check comment. Verify whether any other sibling tickets were affected.

### 3. Act on findings

#### Option A: Request changes (needs-fix)

If there are code quality defects, failing tests, convention violations, or missing edge cases:

1. Submit the review on GitHub:
   ```bash
   gh pr review <pr-number> --request-changes --body "<detailed actionable feedback>"
   ```
2. Swap labels on the PR:
   ```bash
   gh pr edit <pr-number> --remove-label "needs-review" --remove-label "model:strong" --add-label "needs-fix" --add-label "model:weak"
   ```
3. If the review revealed that subsequent tickets' plans need architectural adjustment beyond this PR, open a `needs-replan` escalation ticket blocking the affected tickets.

The PR is now ready for a weak-tier session to fix via `/implement`.

#### Option B: Approve and merge

If the implementation satisfies the plan, acceptance criteria, standards, and tests:

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

