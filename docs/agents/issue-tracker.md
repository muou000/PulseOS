# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --comments`, filtering comments by `jq` and also fetching labels.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close an issue**: `gh issue close <number> --comment "..."`

Infer the repo from `git remote -v`; `gh` does this automatically when run inside a clone.

## Pull requests and reviews

Implementation PRs target `main` and link their ticket via `Closes #<n>`:

- **Open a PR**: `gh pr create --title "..." --body "..." --base main --label "needs-review,model:strong"`
- **Read a PR**: `gh pr view <number> --comments` and `gh pr diff <number>`
- **Review a PR (request changes)**: `gh pr review <number> --request-changes --body "..."`
- **Review a PR (approve)**: `gh pr review <number> --approve --body "..."`
- **Swap PR labels**: `gh pr edit <number> --remove-label "needs-review" --remove-label "model:strong" --add-label "needs-fix" --add-label "model:weak"`
- **Merge a PR**: `gh pr merge <number> --squash --delete-branch` (merging to `main` automatically closes the linked issue).

## Native issue dependencies (Blocking)

Used by `/to-tickets`, `/wayfinder`, and escalation tickets (`/replan`):

- **Add a blocking edge**:
  ```bash
  BLOCKER_ID=$(gh api repos/:owner/:repo/issues/<blocker-number> --jq .id)
  gh api --method POST repos/:owner/:repo/issues/<child-number>/dependencies/blocked_by -F issue_id=$BLOCKER_ID
  ```
- **Check open blockers**:
  GitHub reports open blocking dependencies under `issue_dependencies_summary.blocked_by`. A ticket is unblocked when `issue_dependencies_summary.blocked_by == 0`.
- **Query the frontier**:
  List open issues with `--label "ready-for-agent"` (and optionally `--label "model:weak"`), filtering out any issue where `issue_dependencies_summary.blocked_by > 0` or where an open issue is cited in a manual `Blocked by` line.

## Escalation tickets

When creating an escalation ticket (`needs-replan` or `needs-strong`):

1. Create the issue:
   ```bash
   gh issue create --title "[Escalation] ..." --body "..." --label "needs-replan,model:strong"
   ```
2. For each affected ticket, set the new escalation issue as a blocking dependency using the command above.
3. When resolved in `/replan`, close the escalation issue with `gh issue close <escalation-number> --comment "..."`. This automatically unblocks all affected tickets.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> --comments`.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single issue with **child** issues as tickets.

- **Map**: a single issue labelled `wayfinder:map`, holding the Notes / Decisions-so-far / Fog body. `gh issue create --label wayfinder:map`.
- **Child ticket**: an issue linked to the map as a GitHub sub-issue (`gh api` on the sub-issues endpoint). Where sub-issues aren't enabled, add the child to a task list in the map body and put `Part of #<map>` at the top of the child body. Labels: `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: GitHub's native issue dependencies (see above). Where dependencies aren't available, fall back to a `Blocked by: #<n>, #<n>` line at the top of the child body.
- **Frontier query**: list the map's open children, drop any with an open blocker or an assignee; first in map order wins.
- **Claim**: `gh issue edit <n> --add-assignee @me`.
- **Resolve**: `gh issue comment <n> --body "<answer>"`, then `gh issue close <n>`, then append a context pointer (gist + link) to the map's Decisions-so-far.
