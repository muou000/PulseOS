# axsync safety obligations and validation (#154)

Date: 2026-11-15. Base: `aa3d4f63` (which already contains PR #189).
This follow-up corrects the remaining sentinel/count and proof-documentation
gaps in `modules/axsync/src/{mutex,rwlock}.rs`; it retains the existing public
types, atomic orderings and guard trait bounds.

## Claim, scope and snapshot

The source-level claim is that valid calls to the custom multitask locks grant
only compatible access permissions, publish conflicting accesses in order,
and release each permission at most once. All well-typed safe uses, including
guard transfer and `mem::forget`, are included. Raw unlock callers must satisfy
the documented acquisition/reference-lifetime obligations. No unsafe caller
obligation is silently imposed on `Mutex` or `RwLock`'s safe callers.

The local derivations are beside the implementation and indexed below. This is
not a whole-kernel or binary soundness certification. Under the
`unsafe-rust-review-experimental` verdict rules the universal claim remains
**UNPROVED**: the runtime/dependency premises below have not received an
independent human trust acceptance, and the repository does not pin the full
supported Rust toolchain domain. These residuals are distinct from the two
concrete implementation gaps repaired here. Stress success is execution
evidence, not a universal proof.

Reviewed toolchain: `rustc 1.101.0-nightly
(c1070d69382b8d2f2eb65119c738a77d9e324c9e, 2026-09-28)`, edition 2024.
Dependency: `lock_api 0.4.14`, default features disabled, from `Cargo.lock`.
Skill: `.agents/skills/unsafe-rust-review-experimental` as present at the base.
Source identity and execution results are recorded below after verification.

## Required domain and configuration boundary

`Required(case)` includes every valid call, type `T: ?Sized`, interleaving,
guard lifetime and panic path for the custom source selected by
`axsync/multitask`, on every supported target/toolchain configuration. The
controlling sources are `AGENTS.md`, `modules/axsync/{Cargo.toml,src/lib.rs}`
and the root Makefile. `multitask` and its complement partition selection:
with it these private modules are compiled; without it the exports are aliases
to `kspin`/`spin` and these implementations are not selected. The latter
dependencies' internals are outside this custom-lock audit.

The local algorithms have no target/profile branches. Their symbolic reasoning
therefore applies whenever the recorded atomic/reference premises apply; this
does not establish those premises for an unenumerated toolchain range. The
RISC-V and LoongArch build/run matrix is a sampled subset of `Required`, not
evidence that other configurations are excluded. The Makefile's VF2/LS2K1000
targets use the same custom-lock source but are not runtime-tested here.

No new generator, macro API, FFI or assembly boundary is introduced. Lock fields
and guard constructors remain private to their leaf modules. Abort stops the
execution; an unwind before acquisition grants no token. An unwind while
waiting can strand a writer reservation, reducing progress without granting
access. Guard Drop releases before any notification; a panic there cannot
make an already consumed token accessible again.

## Authority and TCB log (AXSYNC-154-v1)

The matching installed Rust source was read under
`$(rustc --print sysroot)/lib/rustlib/src/rust/library/core/src/`.
These are documentation premises, not deductions from observed machine code.
Links identify the exact source revision; mutable current-web documentation
was not used to extend these guarantees to another release.

| ID | Exact premise and verified authority | Consumers |
| --- | --- | --- |
| R-CELL | `UnsafeCell::get` returns a pointer to the wrapped value; shared references forbid conflicting access, with interior `UnsafeCell` mutation allowed; exclusive references remain unique and storage stays live. “A `&mut T` must always be unique.” [`cell.rs`](https://github.com/rust-lang/rust/blob/c1070d69382b8d2f2eb65119c738a77d9e324c9e/library/core/src/cell.rs), aliasing/layout and `get`/`get_mut` docs. | All three raw reference creations, owned access |
| R-ORDER | Release publishes prior operations to acquiring reads; SeqCst RMW has both Acquire and Release semantics. “For loads it uses `Acquire` ordering. For stores it uses the `Release` ordering.” [`sync/atomic.rs`](https://github.com/rust-lang/rust/blob/c1070d69382b8d2f2eb65119c738a77d9e324c9e/library/core/src/sync/atomic.rs), `Ordering` docs. | M-TOKEN publication, RwLock ORDER chain |
| R-ATOMIC | CAS changes the value only on matching comparison; weak CAS may fail spuriously; fetch arithmetic wraps, so a starting value of one does not prove perpetual nonzero IDs. Same atomic source, `compare_exchange`, `compare_exchange_weak`, `fetch_add` docs. | Token uniqueness and overflow rejection |
| R-TRAIT | “`&T` is `Send` if and only if `T` is `Sync`”; mutable-reference transfer requires `T: Send`. [`marker.rs`](https://github.com/rust-lang/rust/blob/c1070d69382b8d2f2eb65119c738a77d9e324c9e/library/core/src/marker.rs), `Send`/`Sync` docs. | Six RwLock/guard unsafe trait impls |

Additional dependency premises are **pending maintainer acceptance**, not
substitutes for proving the in-scope lock transitions:

| ID/category | Exact proposition, identity and channel | Verification, consumers and limitation |
| --- | --- | --- |
| D-LOCKAPI / UNSAFE-DEP | Selected `lock_api 0.4.14` keeps its mutex allocation borrowed, grants one guard per successful raw acquisition, ties references to guard borrows, and invokes raw unlock once on guard drop; its `Send`/`Sync` bounds preserve payload transfer/sharing. Cargo SemVer dependency, exact resolution in lockfile. | Read registry `src/mutex.rs`, RawMutex contract, Mutex/MutexGuard trait impls, constructors, Deref/DerefMut/Drop. RawMutex's trait safety contract requires actual exclusion. Unsafe wrapper internals are not recursively certified here. |
| D-WAIT / UNSAFE-DEP | Selected in-tree axtask WaitQueue serializes condition checking/enrollment against notification with its queue lock; blocked rescheduling enrolls before releasing that lock. Notification is safe from any kernel task and does not duplicate executing tasks. | Read `wait_queue.rs::wait_until_with_context`, `notify_one_with_context`, `notify_all_with_context` and `run_queue.rs::blocked_resched`. Consumed by wakeup and cross-task-drop arguments; scheduler/context-switch internals remain outside scope. |
| D-TASK / SAFE-DEP | In an initialized kernel task context, `current().id()` provides that context's ID. Zero and collisions are no longer assumed impossible for exclusion. | Read `task.rs::TaskId::new`: wrapping `AtomicU64::fetch_add`. IDs are only diagnostics once nonzero is checked. |

Review owner: PulseOS maintainers. Re-audit all consuming local proofs when
these source/contract identities, enabled features, toolchain, guard bounds or
wait-queue behavior change. No binary backend, linker, hardware or fairness
theorem is claimed. The host adapter below is a test fixture, not a TCB premise
for kernel scheduling.

## Obligation ledger and boundary coverage

| Surface / obligation | Local derivation and exits |
| --- | --- |
| RawMutex new/INIT, lock/try_lock, unlock | M-TOKEN: initialized zero; successful `0 -> checked nonzero` CAS creates one token; failure/panic grants none; the valid unsafe caller consumes it once via Release swap. Acquiring CAS observes publication. Recursion diagnostics do not establish ownership. |
| Mutex alias, guard, payload access | M-TOKEN supplies D-LOCKAPI's exclusion precondition. D-LOCKAPI supplies `UnsafeCell` reference creation, guard borrow scope, drop and trait bounds; no local raw reference operation is hidden by the alias. |
| RwLock new/default, read/try_read, write/try_write | STATE: zero, bounded positive reader tokens, or one writer token at -1. Only CAS creates tokens. Checked reader/waiter increments reject overflow before mutation. Waiting reservations affect admission, never reference permission. |
| Reader release and publication | Every reader acquisition/release is a SeqCst RMW, hence acquires the prior modification and releases its history. By transitivity the last reader decrement carries preceding completed readers to the next writer. Writer Release swap is acquired by the first subsequent token; reader RMWs propagate it. |
| ReadGuard::deref | Stored lock borrow keeps initialized storage/metadata live. Its outstanding reader token excludes writers, ORDER imports prior writes, and the returned reference is bounded by the guard borrow. Legal interior mutation remains subject to `T`'s own safe contract. |
| WriteGuard::deref / deref_mut | Unique writer token excludes every other token; borrowing the same guard excludes conflicting uses of its own references. The lock borrow excludes get_mut/into_inner. ORDER imports prior accesses; DST metadata/alignment are preserved by the cell pointer. |
| All six RwLock/guard Send/Sync impls | Each adjacent proof names the accessible operations: shared guard permits only `&T`, exclusive guard can transfer/move T, shared lock offers both. Guard fields stay private, so sharing a guard cannot expose the lock's write API. Existing conservative bounds are unchanged. |
| Drop, forgotten and transferred guards | Move transfers a token; non-Clone Drop consumes once after reference uses end. Forget retains reservation but leaves no usable guard references. Drop on the destination task does not depend on original task identity. |
| get_mut / into_inner | Exclusive borrow/ownership excludes usable guards even if forgotten tokens leave stale atomic counts; these safe UnsafeCell APIs do not use a state snapshot as reference permission. |
| is_locked / reader_count / is_write_locked | Relaxed snapshots are diagnostics only, including language-reachable doc-hidden methods; none can grant access or mutate a token. |
| Waiting and waking | Release precedes notification. Queue-locked predicate/enrollment either observes availability or is covered by a subsequent notification; acquisition must still win CAS. No FIFO, starvation freedom, recursive RwLock or upgrade guarantee is made. |

The source corrections remove the false inference “ID starts at one, therefore
never zero”, and prevent waiting-writer arithmetic from leaving its stated
nonnegative range. An exhausted count/zero ID now panics before publishing any
state change. Task-ID collisions can still cause conservative recursion panics;
they cannot permit simultaneous acquisitions. Moved guards do not rewrite the
original diagnostic ID; this existing limitation is now explicit.

## Execution evidence

The retained host test uses the actual mutex source and `lock_api 0.4.14` with
a task-ID boundary adapter. On the base, zero-ID `lock` and `try_lock` returned
success without acquiring a nonzero state (both checks FAIL, exit 1). With the
fix both reject before mutation (PASS, exit 0). It creates no data references
on the failing raw paths, so it is a defined contract regression, not a test
that deliberately executes aliased-reference UB. It also checks blocking
reentrancy rejection, continued validity of the original guard, and cross-thread
guard drop. See [the host harness](../../tests/axsync_host/README.md).

The guest suite retains 8,000 mutex updates and four writers plus four readers
checking a two-field value invariant. New checks cover all three guard kinds
transferred to another task, forgotten guards with exclusive owner access, and
writer registration observed through rejected `try_read` while an original
reader remains held. A competing reader must observe the writer's new value.
This establishes admission and progress across release, not the exact instant
at which either task entered the scheduler's sleeping queue. External runner
timeouts bound deadlock detection.

`cargo test -p axsync --lib --no-run` cannot build on the host at the base:
`axalloc` lacks allocator selection and `x86_64 0.15.4` does not implement the
current unstable `Step` methods. These existing failures are outside this patch.
The retained narrow executable avoids those dependencies; actual scheduler
validation uses the prescribed QEMU commands.

| Command | Result |
| --- | --- |
| `cargo run --quiet --locked --offline --manifest-path tests/axsync_host/Cargo.toml` | Four diagnostic groups passed |
| `set -o pipefail; make test 2>&1 \| tail -30` | Both architecture release builds passed |
| `python3 tests/axsync/run.py --arch riscv64 --timeout 60 --log-dir records/axsync-154/rv` | All seven guest groups passed, 8 vCPUs |
| `python3 tests/axsync/run.py --arch loongarch64 --timeout 60 --log-dir records/axsync-154/la` | All seven guest groups passed, 8 vCPUs |

The build output was additionally saved with `tee`; `pipefail` preserved its
exit status. [RISC-V](rv/summary.json) and [LoongArch](la/summary.json) summaries
contain exact QEMU commands, kernel SHA-256 and all check messages. Both use
`disk.img` in snapshot mode and stop after the kernel checks, before userspace
architecture differences matter. Full serial/build logs remain local.

Audited/tested source SHA-256:

```text
d526f0b447fa42bde4b8e2c5022cf7623c71bde1b45767765f0cf737c25e567d  modules/axsync/src/mutex.rs
1fe5b448ac5374b75962cd8afd11bc8e3461fe45101ea6c7a76a72b7f7baee5a  modules/axsync/src/rwlock.rs
5e358a8a8fe77fc8fe5f438e06695ec61e43485d342fb183183494e1649ab2ad  modules/axsync/src/checks.rs
```
