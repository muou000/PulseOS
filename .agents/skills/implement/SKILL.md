---
name: implement
description: "Implement a piece of work based on a spec or set of tickets."
disable-model-invocation: true
---

Implement the work described by the user in the spec or tickets.

If the user passes a ticket reference, fetch it from the issue tracker and state its title before starting. If the reference is ambiguous, ask.

Call the Skill tool with "tdd" where possible, at pre-agreed seams.

Run typechecking regularly, single test files regularly, and the full test suite once at the end.

Once done, call the Skill tool with "code-review" to review the work.

Address and fix any valid findings identified during the code review across both Standards and Spec axes, and re-verify tests and build gates.

Commit your work to the branch.

Push the branch to the remote repository and create a Pull Request with the `pr` skill template using `gh pr create`.
