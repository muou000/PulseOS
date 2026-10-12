---
name: replan
description: "Resolve an escalation ticket (`needs-replan` or `needs-strong`) as the strong tier: verify drift, revise affected tickets' plans and anchors, or unblock stuck implementation, then close the escalation."
disable-model-invocation: true
---

# Replan

Resolve an escalation ticket (`needs-replan` or `needs-strong`) as the strong tier.

Everything you need is on GitHub: read [ticket-workflow.md](../../../docs/agents/ticket-workflow.md) and [issue-tracker.md](../../../docs/agents/issue-tracker.md) first.

## Process

### 1. Load the escalation ticket

Fetch the escalation issue with its comments:

```bash
gh issue view <escalation-issue-number> --comments
```

Identify the type from its label (`needs-replan` or `needs-strong`). Note:
- The parent spec issue
- The list of affected tickets under `## Affected tickets`
- The evidence cited under `## Evidence`
- Any branch/PR under `## Work in progress` (for `needs-strong`)

### 2. Handle `needs-replan`

A weak-tier drift check, review, or implementer flagged that one or more tickets have broken anchors or an outdated plan.

1. **Verify against the codebase**:
   - Check `main` (and any recently merged PRs) for the symbols and modules cited in `## Evidence`.
   - Determine whether each cited anchor is genuinely broken or a false positive.

2. **Branch on outcome**:
   - **False alarm**: The anchor is still sound, or the implementer misread the code.
     - Post a comment on the escalation ticket explaining why the anchor/plan is valid.
     - Close the escalation ticket:
       ```bash
       gh issue close <escalation-issue-number> --comment "False positive: <explanation>"
       ```
     - Closing it clears the native blocker and immediately unblocks the affected tickets.
   - **Confirmed drift**: The code has changed in ways that invalidate the plan or anchors.
     - For each affected ticket:
       - Draft updated `## Implementation plan` and `## Anchors` following the symbol-level rules in `ticket-workflow.md`.
       - Update the ticket body using `gh issue edit <ticket-number> --body "..."`.
       - Comment on the ticket explaining what was adjusted and why (`gh issue comment <ticket-number> --body "..."`).
     - Close the escalation ticket:
       ```bash
       gh issue close <escalation-issue-number> --comment "Replanned affected tickets: <summary of changes>"
       ```
     - Closing it clears the blocker and allows the weak tier to pick up the revised tickets.

### 3. Handle `needs-strong`

An implementer got stuck on a plan step, or verification failed after 3 attempts.

1. **Investigate the root cause**:
   - Check out the WIP branch:
     ```bash
     git fetch origin && git checkout <wip-branch>
     ```
   - Inspect the failure and git diff. Run the failing verification command from `AGENTS.md`.

2. **Resolve**:
   - **If the plan needs architectural revision**: Update the ticket's `## Implementation plan` and `## Anchors` to account for the technical obstacle. If the remaining work is suited for the weak tier, push the branch, remove any blockers, and close the escalation ticket with guidance.
   - **If the obstacle requires strong-tier implementation**: Complete the difficult step yourself using `tdd`, ensure verification passes, push to the PR branch, and close the escalation ticket. The PR can then enter `/review-ticket`.

