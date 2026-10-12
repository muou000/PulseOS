---
name: to-tickets
description: Break a plan, spec, or the current conversation into tracer-bullet tickets, each carrying a symbol-level implementation plan, checkable anchors and its blocking edges, published to GitHub for weak-tier implementers.
disable-model-invocation: true
---

# To Tickets

Break a plan, spec, or conversation into a set of **tickets**: tracer-bullet vertical slices, each declaring the tickets that **block** it, and each carrying a plan a weak-tier model can follow in a fresh session.

This is strong-tier work. Read [ticket-workflow.md](../../../docs/agents/ticket-workflow.md) first: it defines the tiers, the ticket shape, the implementation plan's granularity, and anchors. The issue tracker and triage label vocabulary should have been provided to you. If not, tell the user to run `/setup-matt-pocock-skills`.

## Process

### 1. Gather context

Work from whatever is already in the conversation context. If the user passes a reference (a spec path, an issue number or URL) as an argument, fetch it and read its full body and comments.

### 2. Explore the codebase

Explore every area the work touches until you can name the crates, modules, types and functions each slice changes. Plans and anchors are written from this reading, so an anchor you haven't verified in the code is a guess. Ticket titles and descriptions should use the project's domain glossary vocabulary, and respect ADRs in the area you're touching.

Look for opportunities to prefactor the code to make the implementation easier. "Make the change easy, then make the easy change."

### 3. Draft vertical slices

Break the work into **tracer bullet** tickets.

<vertical-slice-rules>

- Each slice cuts a narrow but COMPLETE path through every layer it touches, tests included: vertical, NOT a horizontal slice of one layer
- A completed slice is verifiable on its own and keeps `main` green, since each ticket's PR merges straight to `main`
- Each slice is sized to fit in a single fresh context window of a weak-tier model
- Any prefactoring should be done first

</vertical-slice-rules>

Give each ticket its **blocking edges**: the other tickets that must complete before it can start. A ticket with no blockers can start immediately.

**Wide refactors are the exception to vertical slicing.** A **wide refactor** is one mechanical change (rename a column, retype a shared symbol) whose **blast radius** fans across the whole codebase, so a single edit breaks thousands of call sites at once and no vertical slice can land green. Don't force it into a tracer bullet; sequence it as **expand–contract**. First expand: add the new form beside the old so nothing breaks. Then migrate the call sites over in batches sized by blast radius (per package, per directory), each batch its own ticket blocked by the expand, keeping CI green batch to batch because the old form still exists. Finally contract: delete the old form once no caller remains, in a ticket blocked by every migrate batch.

### 4. Quiz the user

Present the proposed breakdown as a numbered list. For each ticket, show:

- **Title**: short descriptive name
- **Blocked by**: which other tickets (if any) must complete first
- **What it delivers**: the end-to-end behaviour this ticket makes work
- **Key anchors**: the facts about the code its plan will depend on

Ask the user:

- Does the granularity feel right? (too coarse / too fine)
- Are the blocking edges correct: does each ticket only depend on tickets that genuinely gate it?
- Should any tickets be merged or split further?

Iterate until the user approves the breakdown.

### 5. Write each ticket's plan and anchors

For each approved ticket, write the **Implementation plan** and **Anchors** sections as ticket-workflow.md defines them. Cross-check across tickets: an anchor that cites a symbol an earlier ticket introduces must match that ticket's plan exactly (name, signature, module), and must name that ticket.

Done when every plan step names its symbols and its verification, and every fact a plan relies on appears as an anchor.

### 6. Publish the tickets to GitHub

Publish one issue per ticket in dependency order (blockers first) so each ticket's blocking edges can reference real identifiers:

- Body in the ticket shape from ticket-workflow.md.
- Labels: `model:weak` and `ready-for-agent`.
- Sub-issue of the parent spec when the source was an existing issue.
- Blockers set as native issue dependencies.

Do NOT close or modify any parent issue.

Finish by listing the published tickets with their blockers, and the current **frontier** (tickets with no open blockers): those are ready for `/implement` in fresh weak-tier sessions.

In ticket bodies, write code only where ticket-workflow.md allows it (public signatures, type shapes). Exception: if a prototype produced a snippet that encodes a decision more precisely than prose can (state machine, reducer, schema), inline the decision-rich part and note it came from a prototype.
