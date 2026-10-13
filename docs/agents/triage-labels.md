# Triage Labels

The skills speak in terms of canonical triage roles, model tiers, and PR/escalation workflow states. This file maps those roles to the label strings used in this repo's issue tracker.

## Canonical triage roles

| Label in mattpocock/skills | Label in our tracker | Meaning                                  |
| -------------------------- | -------------------- | ---------------------------------------- |
| `needs-triage`             | `needs-triage`       | Maintainer needs to evaluate this issue  |
| `needs-info`               | `needs-info`         | Waiting on reporter for more information |
| `ready-for-agent`          | `ready-for-agent`    | Fully specified, ready for an AFK agent  |
| `ready-for-human`          | `ready-for-human`    | Requires human implementation            |
| `wontfix`                  | `wontfix`            | Will not be actioned                     |

## Model tier labels

Carried on every issue and PR to indicate which model tier should claim it.

| Label | Meaning |
| ----- | ------- |
| `model:strong` | Requires a strong-tier model (e.g. Claude Opus / Gemini Pro) for architecture, planning, goal alignment audit, replanning, or escalation resolution |
| `model:weak`   | Handled by a weak-tier model (e.g. Flash / Sonnet) for implementation, TDD, routine code review, fixes, and drift checks |

## PR workflow labels

Used on pull requests to manage review handoffs between implementers and reviewers.

| Label | Meaning |
| ----- | ------- |
| `needs-review` | PR implementation and routine self-review complete, drift check passed; ready for strong-tier goal audit via `/review-ticket` |
| `needs-fix`    | PR review requested changes; ready for weak-tier fixes via `/implement` |

## Escalation labels

Used on escalation issues that block affected tickets until resolved.

| Label | Meaning |
| ----- | ------- |
| `needs-replan` | An anchor or plan step is invalidated by code drift; blocks affected tickets until replanned via `/replan` |
| `needs-strong` | Implementer is blocked or verification failed repeatedly (3 attempts); blocks current ticket until resolved via `/replan` |
