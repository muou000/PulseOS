use alloc::{format, string::String, vec::Vec};

use bpf_capture::{
    CaptureArch, CaptureScope, CaptureWriter, CounterKind, DiagnosticCounter, DiagnosticIdentity,
    RecorderSource, RuntimeDiagnostics, SchemaRegistry, SessionConfig,
    recorder::{SourceClock, SourceConfig, SourceFallback, SourceUnit},
};
use bpf_record::{
    Capabilities, Event, Options, SessionPlan, SourcePlan,
    observation::{JOURNAL_READ_LIMIT, KERNEL_ELF_READ_LIMIT, Observation},
};
use sha2::{Digest, Sha256};

use crate::sys::{self, Fd, Mapping, Result, Signals};

fn log(message: &str) {
    sys::print(&format!("RECORD {message}\n"));
}
fn log_heap(stage: &str) {
    let heap = sys::heap_resources();
    log(&format!(
        "HEAP stage={stage} reserved_bytes={} used_bytes={} allocated_bytes={} \
         peak_allocated_bytes={}",
        heap.reserved_bytes, heap.used_bytes, heap.allocated_bytes, heap.peak_allocated_bytes
    ));
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn number(line: &str, key: &str) -> Option<u64> {
    line.split_whitespace()
        .filter_map(|word| word.split_once('='))
        .find(|(name, _)| *name == key)?
        .1
        .parse()
        .ok()
}
fn snapshot() -> Result<String> {
    let text = sys::read_file("/proc/pulse_bpf_stats", 64 * 1024)?;
    if !text.starts_with("PULSE_BPF_STATS version=1 ")
        || !text.lines().last().is_some_and(|s| s.starts_with("END "))
    {
        return Err("incomplete BPF diagnostics".into());
    }
    Ok(text)
}
fn mapping_snapshot(fail: bool) -> Result<String> {
    // Opening proc freezes a complete ordered cut. The acceptance hook uses an
    // actually absent path so descriptor cleanup exercises the syscall failure.
    let path = if fail {
        "/proc/pulse_bpf_mappings_missing"
    } else {
        "/proc/pulse_bpf_mappings"
    };
    sys::read_file(path, JOURNAL_READ_LIMIT)
}
fn event_row(text: &str, fd: usize) -> Result<&str> {
    text.lines()
        .find(|s| s.starts_with("EVENT ") && number(s, "fd") == Some(fd as u64))
        .ok_or("missing source diagnostics".into())
}
fn totals(text: &str) -> (u64, u64) {
    let line = text.lines().last().unwrap_or("");
    (
        number(line, "events").unwrap_or(u64::MAX),
        number(line, "programs").unwrap_or(u64::MAX),
    )
}
fn system_counts(text: &str) -> Result<(u64, u64)> {
    let header = text.lines().next().ok_or("missing diagnostics header")?;
    Ok((
        number(header, "registered_events").ok_or("missing event registry diagnostics")?,
        number(header, "trace_subscriptions").ok_or("missing trace subscription diagnostics")?,
    ))
}
fn global_number(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find(|line| line.starts_with("GLOBAL "))
        .and_then(|line| number(line, key))
}
fn delta(before: Option<&str>, after: Option<&str>, key: &str) -> Option<u64> {
    before
        .and_then(|line| number(line, key))
        .zip(after.and_then(|line| number(line, key)))
        .and_then(|(before, after)| after.checked_sub(before))
}
fn snapshot_value(after: Option<&str>, key: &str) -> Option<u64> {
    after.and_then(|line| number(line, key))
}

#[derive(Default)]
struct Hooks {
    fail_load: usize,
    fail_attach: usize,
    detached_ms: u64,
    write_fail_after: Option<usize>,
    dup_close: bool,
    stop_failure: bool,
    fail_snapshot: bool,
    fail_journal: bool,
}
fn parse(args: &[&str]) -> Result<(Options, Hooks)> {
    #[allow(unused_mut)]
    let mut hooks = Hooks::default();
    let mut clean = Vec::new();
    let mut i = 0;
    while i < args.len() {
        #[cfg(feature = "acceptance")]
        if args[i].starts_with("--test-") {
            if args[i] == "--test-fail-snapshot" || args[i] == "--test-fail-journal" {
                if args[i] == "--test-fail-snapshot" {
                    hooks.fail_snapshot = true;
                } else {
                    hooks.fail_journal = true;
                }
                i += 1;
                continue;
            }
            if args[i] == "--test-stop-failure" {
                hooks.stop_failure = true;
                i += 1;
                continue;
            }
            if args[i] == "--test-dup-close" {
                hooks.dup_close = true;
                i += 1;
                continue;
            }
            let value = args
                .get(i + 1)
                .ok_or("missing acceptance option value")?
                .parse::<usize>()
                .map_err(|_| "invalid acceptance value")?;
            match args[i] {
                "--test-fail-load" => hooks.fail_load = value,
                "--test-fail-attach" => hooks.fail_attach = value,
                "--test-detached" => hooks.detached_ms = value as u64,
                "--test-write-fail-after" => hooks.write_fail_after = Some(value),
                _ => return Err("unknown acceptance option".into()),
            }
            i += 2;
            continue;
        }
        clean.push(args[i]);
        i += 1;
    }
    Ok((Options::parse(&clean)?, hooks))
}

#[derive(Default)]
struct ControlErrors {
    count: u64,
    first: Option<String>,
}
impl ControlErrors {
    fn record(&mut self, error: String) {
        self.count = self.count.saturating_add(1);
        if self.first.is_none() {
            self.first = Some(error);
        }
    }
    fn observe<T>(&mut self, result: Result<T>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.record(error);
                None
            }
        }
    }
}

fn create_map(kind: u32, value_size: u32, entries: u32) -> Result<Fd> {
    let mut attr = [0u8; 72];
    put32(&mut attr, 0, kind);
    put32(&mut attr, 4, 4);
    put32(&mut attr, 8, value_size);
    put32(&mut attr, 12, entries);
    // SAFETY: MAP_CREATE's attr consists only of scalars and zero optional fields.
    unsafe { Fd::bpf(0, &attr) }
}
fn bind(map: &Fd, cpu: u32, sink: &Fd) -> Result<()> {
    let value = sink.number() as u32;
    let mut attr = [0u8; 32];
    put32(&mut attr, 0, map.number() as u32);
    put64(&mut attr, 8, &cpu as *const u32 as u64);
    put64(&mut attr, 16, &value as *const u32 as u64);
    // SAFETY: key/value point to initialized 4-byte locals matching map geometry.
    unsafe { sys::bpf_call(2, &mut attr) }
}
fn perf(kind: u32, config: u64, pid: isize, cpu: isize, period: u64) -> Result<Fd> {
    let mut attr = [0u8; 64];
    put32(&mut attr, 0, kind);
    put32(&mut attr, 4, 64);
    put64(&mut attr, 8, config);
    put64(&mut attr, 16, period);
    put64(&mut attr, 24, 1 << 10);
    put64(&mut attr, 40, 1);
    Fd::perf(&attr, pid, cpu)
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Insn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}
struct Program(Vec<Insn>);
impl Program {
    fn emit(&mut self, code: u8, dst: u8, src: u8, off: i16, imm: i32) {
        self.0.push(Insn {
            code,
            regs: dst | (src << 4),
            off,
            imm,
        });
    }
    fn map(&mut self, reg: u8, fd: &Fd) {
        self.emit(0x18, reg, 1, 0, fd.number() as i32);
        self.emit(0, 0, 0, 0, 0);
    }
}
fn load(source: &SourcePlan, scratch: &Fd, outputs: &Fd, fail: bool) -> Result<Fd> {
    let mut p = Program(Vec::new());
    p.emit(0xbf, 6, 1, 0, 0);
    p.emit(
        0x61,
        2,
        6,
        if source.event.is_software() { 24 } else { 16 },
        0,
    );
    p.emit(0x63, 10, 2, -4, 0);
    p.map(1, scratch);
    p.emit(0xbf, 2, 10, 0, 0);
    p.emit(0x07, 2, 0, 0, -4);
    p.emit(0x85, 0, 0, 0, 1);
    let jump = p.0.len();
    p.emit(0x15, 0, 0, 0, 0);
    p.emit(0xbf, 7, 0, 0, 0);
    p.emit(0x62, 7, 0, 0, 0x31524250);
    p.emit(0x62, 7, 0, 4, 1 | ((source.kind as i32) << 16));
    p.emit(0x62, 7, 0, 8, source.context_size() as i32);
    p.emit(0x62, 7, 0, 12, source.id as i32);
    p.emit(0x7a, 7, 0, 16, 0);
    for offset in (0..source.context_size()).step_by(8) {
        p.emit(0x79, 8, 6, offset as i16, 0);
        p.emit(0x7b, 7, 8, (24 + offset) as i16, 0);
    }
    p.emit(0xbf, 1, 6, 0, 0);
    p.map(2, outputs);
    p.emit(0x18, 3, 0, 0, -1);
    p.emit(0, 0, 0, 0, 0);
    p.emit(0xbf, 4, 7, 0, 0);
    p.emit(0xb7, 5, 0, 0, (24 + source.context_size()) as i32);
    p.emit(0x85, 0, 0, 0, 25);
    let ret = p.0.len();
    p.emit(0xb7, 0, 0, 0, 0);
    p.emit(0x95, 0, 0, 0, 0);
    p.0[jump].off = (ret - jump - 1) as i16;
    if fail {
        p.0[0].code = 0xff;
    }
    let mut attr = [0u8; 144];
    let mut verifier = [0u8; 2048];
    put32(&mut attr, 0, if source.event.is_software() { 7 } else { 5 });
    put32(&mut attr, 4, p.0.len() as u32);
    put64(&mut attr, 8, p.0.as_ptr() as u64);
    put64(&mut attr, 16, c"GPL".as_ptr() as u64);
    put32(&mut attr, 24, 1);
    put32(&mut attr, 28, verifier.len() as u32);
    put64(&mut attr, 32, verifier.as_mut_ptr() as u64);
    // SAFETY: repr(C) Insn has the 8-byte BPF layout; full instruction Vec and
    // NUL license stay live, verifier buffer is exclusively writable for its bound.
    let result = unsafe { Fd::bpf(5, &attr) };
    if result.is_err() {
        let end = verifier
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(verifier.len());
        log(&format!(
            "VERIFIER {}",
            core::str::from_utf8(&verifier[..end]).unwrap_or("non-UTF8")
        ));
    }
    result
}
fn attach(program: &Fd, event: &Fd, fail: bool) -> Result<Fd> {
    let mut attr = [0u8; 64];
    put32(&mut attr, 0, program.number() as u32);
    put32(&mut attr, 4, event.number() as u32);
    put32(&mut attr, 8, if fail { u32::MAX } else { 41 });
    // SAFETY: LINK_CREATE attr contains descriptor/scalar fields only.
    unsafe { Fd::bpf(28, &attr) }
}
enum Resource {
    Fd(Fd),
    Mapping(Mapping),
}
struct Ring {
    fd: usize,
    mapping: usize,
    cpu: u32,
    tail: u64,
}
struct Source {
    fd: usize,
    link: Option<usize>,
    scratch_map_id: u32,
    binding: RecorderSource,
    raw_samples: u64,
    retained_samples: u64,
}
struct Session {
    resources: Vec<Resource>,
    rings: Vec<Ring>,
    sources: Vec<Source>,
    output_map_id: u32,
}
impl Session {
    fn new() -> Self {
        Self {
            resources: Vec::new(),
            rings: Vec::new(),
            sources: Vec::new(),
            output_map_id: 0,
        }
    }
    fn fd(&self, index: usize) -> &Fd {
        match &self.resources[index] {
            Resource::Fd(fd) => fd,
            _ => unreachable!(),
        }
    }
    fn add_fd(&mut self, fd: Fd) -> usize {
        let index = self.resources.len();
        self.resources.push(Resource::Fd(fd));
        index
    }
    fn prepare(&mut self, plan: &SessionPlan, hooks: &Hooks) -> Result<()> {
        let entries = plan
            .sink_cpus
            .iter()
            .max()
            .copied()
            .ok_or("no online CPUs")?
            + 1;
        let outputs = self.add_fd(create_map(4, 4, entries)?);
        self.output_map_id = self.fd(outputs).object_id()?;
        for &cpu in &plan.sink_cpus {
            let fd = self.add_fd(perf(1, 10, -1, cpu as isize, 0)?);
            let mapping = Mapping::ring(self.fd(fd), (plan.options.buffer_pages + 1) * 4096)?;
            let index = self.resources.len();
            self.resources.push(Resource::Mapping(mapping));
            bind(self.fd(outputs), cpu, self.fd(fd))?;
            self.rings.push(Ring {
                fd,
                mapping: index,
                cpu,
                tail: 0,
            });
        }
        for (index, source) in plan.sources.iter().enumerate() {
            let scratch = self.add_fd(create_map(2, (24 + source.context_size()) as u32, entries)?);
            let program = self.add_fd(load(
                source,
                self.fd(scratch),
                self.fd(outputs),
                hooks.fail_load == index + 1,
            )?);
            let event = self.add_fd(perf(
                source.event.perf_type(),
                source.event.config(),
                source.tid.map_or(-1, |t| t as isize),
                source.cpu.map_or(-1, |c| c as isize),
                source.period_ns,
            )?);
            let link = if hooks.detached_ms == 0 {
                Some(self.add_fd(attach(
                    self.fd(program),
                    self.fd(event),
                    hooks.fail_attach == index + 1,
                )?))
            } else {
                None
            };
            self.sources.push(Source {
                fd: event,
                link,
                scratch_map_id: self.fd(scratch).object_id()?,
                raw_samples: 0,
                retained_samples: 0,
                binding: RecorderSource {
                    id: source.id,
                    kind: source.kind,
                    event_id: source.event_id(),
                    schema_version: source.schema_version(),
                    scope: source.cpu.map_or_else(
                        || CaptureScope::Task(source.tid.unwrap() as u64),
                        |c| CaptureScope::PerCpu(c),
                    ),
                    sample_period: source.period_ns,
                    clock: SourceClock::Monotonic,
                    config: source.event.source_config(),
                    requested_config: source.requested_config,
                    requested_sample_period: if source.event.is_software()
                        && plan.options.frequency.is_some()
                    {
                        0
                    } else {
                        source.period_ns
                    },
                    requested_frequency_hz: if source.event.is_software() {
                        plan.options.frequency.unwrap_or(0)
                    } else {
                        0
                    },
                    // The actual perf request uses period mode. This is not an
                    // assertion that the requested frequency was achieved.
                    effective_frequency_hz: 0,
                    requested_buffer_pages: plan.options.buffer_pages as u64,
                    effective_buffer_pages: plan.options.buffer_pages as u64,
                    unit: if source.event.is_software() {
                        SourceUnit::Nanoseconds
                    } else {
                        SourceUnit::Events
                    },
                    fallback: if source.requested_config == SourceConfig::HardwareCycles {
                        SourceFallback::HardwareUnavailable
                    } else {
                        SourceFallback::None
                    },
                    kernel_event_id: 0,
                    bound_task_id: 0,
                    program_id: self.fd(program).object_id()?,
                    link_id: link
                        .map(|link| self.fd(link).object_id())
                        .transpose()?
                        .unwrap_or(0),
                    enable_before_ns: 0,
                    enable_after_ns: 0,
                    disable_before_ns: 0,
                    disable_after_ns: 0,
                },
            });
        }
        let stats = snapshot()?;
        for i in 0..self.sources.len() {
            let row = event_row(&stats, self.fd(self.sources[i].fd).number())?;
            if number(row, "enabled") != Some(0) || number(row, "inflight") != Some(0) {
                return Err("source enabled during prepare".into());
            }
            self.sources[i].binding.kernel_event_id =
                number(row, "id").ok_or("missing kernel event identity")?;
            self.sources[i].binding.bound_task_id =
                number(row, "task_id").ok_or("missing stable task identity")?;
        }
        for ring in &self.rings {
            let row = event_row(&stats, self.fd(ring.fd).number())?;
            if number(row, "enabled") != Some(0) {
                return Err("sink enabled during prepare".into());
            }
        }
        log(&format!(
            "PREPARED sources={} sinks={} enabled=0",
            self.sources.len(),
            self.rings.len()
        ));
        let resources = sys::resources();
        let system = system_counts(&stats)?;
        log(&format!(
            "RESOURCES owned_fds={} mapped_bytes={} capture_budget={} registered_events={} \
             trace_subscriptions={}",
            resources.0, resources.1, plan.options.record_bytes, system.0, system.1
        ));
        log_heap("prepared");
        Ok(())
    }
    fn enable(&mut self) -> Result<()> {
        for ring in &self.rings {
            self.fd(ring.fd).enable(true)?;
        }
        for i in 0..self.sources.len() {
            let before = sys::now()?;
            self.fd(self.sources[i].fd).enable(true)?;
            let after = sys::now()?;
            self.sources[i].binding.enable_before_ns = before;
            self.sources[i].binding.enable_after_ns = after;
            log(&format!(
                "ENABLE source={} before={before} after={after}",
                self.sources[i].binding.id
            ));
        }
        Ok(())
    }
    fn disable(&mut self, errors: &mut ControlErrors) -> bool {
        // Every source receives a disable attempt even when another control
        // operation fails. Retry sources whose complete observed control window
        // is still unknown; never synthesize a timestamp for a failed clock read.
        for _ in 0..2 {
            for i in (0..self.sources.len()).rev() {
                if self.sources[i].binding.disable_after_ns != 0 {
                    continue;
                }
                let before = errors.observe(sys::now());
                let disabled = errors.observe(self.fd(self.sources[i].fd).enable(false));
                let after = errors.observe(sys::now());
                if let (Some(before), Some(()), Some(after)) = (before, disabled, after) {
                    self.sources[i].binding.disable_before_ns = before;
                    self.sources[i].binding.disable_after_ns = after;
                    log(&format!(
                        "DISABLE source={} before={before} after={after}",
                        self.sources[i].binding.id
                    ));
                }
            }
        }
        // Detach immediately after disabling so no new tracepoint records can
        // enter the handoff queues while the final drain barrier is observed.
        let detached = self.detach_sources(errors);
        let start = errors.observe(sys::now());
        // The poll bound also prevents an unbounded retry if the clock itself
        // is broken. It is not presented as measured elapsed time.
        for _ in 0..2000 {
            if let Some(stats) = errors.observe(snapshot()) {
                let mut ready = true;
                for source in &self.sources {
                    match errors.observe(event_row(&stats, self.fd(source.fd).number())) {
                        Some(row) => {
                            ready &= number(row, "enabled") == Some(0)
                                && number(row, "inflight") == Some(0)
                        }
                        None => ready = false,
                    }
                }
                let trace_queue_state = global_number(&stats, "trace_queued");
                // The handoff queue is part of the stop barrier. A snapshot
                // without its occupancy field cannot prove that accepted
                // tracepoint records have reached the consumer.
                ready &= trace_queue_state == Some(0);
                ready &= detached;
                if ready {
                    log("QUIESCENT inflight=0 trace_queued=0");
                    return true;
                }
            }
            if let Some((start, now)) = start.zip(errors.observe(sys::now())) {
                if now.saturating_sub(start) > 2_000_000_000 {
                    break;
                }
            }
            if errors.observe(sys::sleep_ms(1)).is_none() {
                break;
            }
        }
        errors.record("VM quiescence was not established".into());
        false
    }
    fn drain(
        &mut self,
        writer: &mut CaptureWriter,
        records: &mut u64,
        lost: &mut u64,
        per_ring_budget: usize,
    ) -> Result<()> {
        for ring in &mut self.rings {
            let Resource::Mapping(mapping) = &self.resources[ring.mapping] else {
                unreachable!()
            };
            let head = mapping.head();
            let mut consumed = 0;
            // Active collection has a finite fair budget on each CPU so a busy
            // producer cannot postpone duration, signal or target-exit checks.
            // After quiescence callers use usize::MAX to exhaust finite rings.
            while ring.tail != head && consumed < per_ring_budget {
                let mut header = [0u8; 8];
                mapping.copy_published(ring.tail, head, ring.tail, &mut header)?;
                let size = u16::from_le_bytes([header[6], header[7]]) as usize;
                // PERF_SAMPLE_RAW framing (12) + source envelope (24) + the
                // current stack context (640), padded to eight bytes.
                if size < 8 || size > 680 || size % 8 != 0 {
                    return Err("invalid record extent".into());
                }
                let mut frame = [0u8; 680];
                mapping.copy_published(ring.tail, head, ring.tail, &mut frame[..size])?;
                let kind = u32::from_le_bytes(header[..4].try_into().unwrap());
                let accepted = writer
                    .ingest_recorder_frame(ring.cpu, &frame[..size])
                    .map_err(|e| format!("capture record: {e:?}"));
                // The extent was validated against acquired head. Even a bad
                // envelope is consumed once, while writer records corruption.
                ring.tail = ring.tail.wrapping_add(size as u64);
                mapping.tail(ring.tail);
                let accepted = accepted?;
                consumed += 1;
                if kind == 9 {
                    let source_id = u32::from_le_bytes(frame[24..28].try_into().unwrap());
                    let source = self
                        .sources
                        .iter_mut()
                        .find(|s| s.binding.id == source_id)
                        .ok_or("validated record lost source binding")?;
                    source.raw_samples += 1;
                    source.retained_samples += u64::from(accepted);
                }
                if kind == 9 && accepted {
                    *records += 1;
                }
                if kind == 2 && size == 24 {
                    *lost =
                        lost.saturating_add(u64::from_le_bytes(frame[16..24].try_into().unwrap()));
                }
            }
        }
        Ok(())
    }
    fn duplicate_sources(&mut self) -> Result<()> {
        for i in 0..self.sources.len() {
            let index = self.sources[i].fd;
            let copy = self.fd(index).duplicate()?;
            let old = core::mem::replace(&mut self.resources[index], Resource::Fd(copy));
            drop(old);
        }
        log("DUP_CLOSE originals_closed=1 retained=1");
        Ok(())
    }
    fn target_alive(&self) -> Result<bool> {
        if !self
            .sources
            .iter()
            .any(|s| matches!(s.binding.scope, CaptureScope::Task(_)))
        {
            return Ok(true);
        }
        let stats = snapshot()?;
        for source in &self.sources {
            if !matches!(source.binding.scope, CaptureScope::Task(_)) {
                continue;
            }
            let row = event_row(&stats, self.fd(source.fd).number())?;
            if number(row, "task_id") != Some(source.binding.bound_task_id) {
                return Err("bound task identity changed".into());
            }
            match number(row, "target_alive") {
                Some(0) => return Ok(false),
                Some(1) => {}
                _ => return Err("task liveness unavailable".into()),
            }
        }
        Ok(true)
    }
    fn detach_sources(&self, errors: &mut ControlErrors) -> bool {
        let mut detached = true;
        for source in self.sources.iter().rev() {
            if let Some(link) = source.link {
                detached &= errors.observe(self.fd(link).detach_link()).is_some();
            }
        }
        detached
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        for source in &self.sources {
            let _ = self.fd(source.fd).enable(false);
        }
        for ring in &self.rings {
            let _ = self.fd(ring.fd).enable(false);
        }
        while let Some(resource) = self.resources.pop() {
            drop(resource);
        }
    }
}

fn diagnostics(
    plan: &SessionPlan,
    session: &Session,
    before: &str,
    after: &str,
    reason: &str,
    records: u64,
) -> RuntimeDiagnostics {
    let mut d = RuntimeDiagnostics::default();
    d.identities.push(DiagnosticIdentity {
        name: "recorder_config".into(),
        value: Some(plan.evidence()),
    });
    for name in ["registered_events", "trace_subscriptions"] {
        for (point, text) in [("before", before), ("after", after)] {
            d.counters.push(DiagnosticCounter {
                name: format!("{name}_{point}"),
                scope: "system".into(),
                value: text.lines().next().and_then(|header| number(header, name)),
                kind: CounterKind::Activity,
            });
        }
    }
    d.identities.push(DiagnosticIdentity {
        name: "stop_reason".into(),
        value: Some(reason.into()),
    });
    d.identities.push(DiagnosticIdentity {
        name: "output_map_id".into(),
        value: Some(format!("{}", session.output_map_id)),
    });
    for (name, text) in [
        ("kernel_stats_before", before),
        ("kernel_stats_after", after),
    ] {
        d.identities.push(DiagnosticIdentity {
            name: name.into(),
            value: if text.is_empty() {
                None
            } else {
                Some(text.into())
            },
        });
    }
    let before_global = before.lines().find(|line| line.starts_with("GLOBAL "));
    let after_global = after.lines().find(|line| line.starts_with("GLOBAL "));
    for name in [
        "timer_enqueued",
        "timer_dequeued",
        "timer_full",
        "timer_busy",
        "trace_enqueued",
        "trace_dequeued",
        "trace_full",
        "trace_recursive",
        "fault_started",
        "fault_completed",
        "fault_clock_errors",
    ] {
        d.counters.push(DiagnosticCounter {
            name: name.into(),
            scope: "system".into(),
            value: delta(before_global, after_global, name),
            kind: match name {
                "timer_full" | "timer_busy" | "trace_full" | "trace_recursive" => CounterKind::Loss,
                "fault_clock_errors" => CounterKind::Error,
                _ => CounterKind::Activity,
            },
        });
    }
    for (name, kind) in [
        ("trace_queued", CounterKind::Activity),
        ("trace_high_water", CounterKind::Activity),
        ("trace_queue_capacity", CounterKind::Activity),
    ] {
        d.counters.push(DiagnosticCounter {
            name: name.into(),
            scope: "system".into(),
            value: snapshot_value(after_global, name),
            kind,
        });
    }
    d.counters.push(DiagnosticCounter {
        name: "retained_records".into(),
        scope: "consumer".into(),
        value: Some(records),
        kind: CounterKind::Activity,
    });
    // No source-scoped resolver ownership exists in the current ABI. VM
    // quiescence does not prove pending sleepable faults have completed.
    if plan.sources.iter().any(|s| s.event == Event::Fault) {
        d.counters.push(DiagnosticCounter {
            name: "pending_fault_resolvers".into(),
            scope: "session".into(),
            value: None,
            kind: CounterKind::Activity,
        });
    }
    for source in &session.sources {
        let fd = session.fd(source.fd).number();
        let a = event_row(before, fd).ok();
        let b = event_row(after, fd).ok();
        d.identities.push(DiagnosticIdentity {
            name: format!("source_{}_task_id", source.binding.id),
            value: a
                .and_then(|row| number(row, "task_id"))
                .map(|id| format!("{id}")),
        });
        d.identities.push(DiagnosticIdentity {
            name: format!("source_{}_scratch_map_id", source.binding.id),
            value: Some(format!("{}", source.scratch_map_id)),
        });
        let program_before = before.lines().find(|row| {
            row.starts_with("PROGRAM ")
                && number(row, "id") == Some(source.binding.program_id as u64)
        });
        let program_after = after.lines().find(|row| {
            row.starts_with("PROGRAM ")
                && number(row, "id") == Some(source.binding.program_id as u64)
        });
        let runs = delta(program_before, program_after, "runs");
        let errors = delta(program_before, program_after, "errors");
        for (name, value, kind) in [
            ("runs", runs, CounterKind::Activity),
            ("errors", errors, CounterKind::Error),
        ] {
            d.counters.push(DiagnosticCounter {
                name: name.into(),
                scope: format!("program:{}", source.binding.program_id),
                value,
                kind,
            });
        }
        let delivered = delta(a, b, "delivered");
        let successful = runs
            .zip(errors)
            .and_then(|(runs, errors)| runs.checked_sub(errors));
        for (name, value, kind) in [
            (
                "program_delivery_discrepancy",
                successful.zip(delivered).map(|(a, b)| a.abs_diff(b)),
                CounterKind::Error,
            ),
            (
                "raw_samples",
                Some(source.raw_samples),
                CounterKind::Activity,
            ),
            (
                "retained_samples",
                Some(source.retained_samples),
                CounterKind::Activity,
            ),
            (
                "export_discarded",
                Some(source.raw_samples - source.retained_samples),
                CounterKind::Loss,
            ),
            (
                "emission_gap",
                delivered.and_then(|count| count.checked_sub(source.raw_samples)),
                CounterKind::Loss,
            ),
        ] {
            d.counters.push(DiagnosticCounter {
                name: name.into(),
                scope: format!("source:{}", source.binding.id),
                value,
                kind,
            });
        }
        for name in [
            "observed",
            "delivered",
            "skipped",
            "cancelled",
            "invalid",
            "reentry",
            "helper",
            "budget",
            "transport_lost",
            "consumer_corrupt",
            "consumer_bounds",
        ] {
            let value = delta(a, b, name);
            let kind = match name {
                "observed" | "delivered" => CounterKind::Activity,
                "skipped" | "cancelled" | "transport_lost" => CounterKind::Loss,
                _ => CounterKind::Error,
            };
            d.counters.push(DiagnosticCounter {
                name: name.into(),
                scope: format!("source:{}", source.binding.id),
                value,
                kind,
            });
        }
    }
    for ring in &session.rings {
        let fd = session.fd(ring.fd).number();
        for name in ["transport_lost", "consumer_corrupt", "consumer_bounds"] {
            let value = event_row(before, fd)
                .ok()
                .and_then(|row| number(row, name))
                .zip(event_row(after, fd).ok().and_then(|row| number(row, name)))
                .and_then(|(a, b)| b.checked_sub(a));
            d.counters.push(DiagnosticCounter {
                name: name.into(),
                scope: format!("sink:{}", ring.cpu),
                value,
                kind: if name == "transport_lost" {
                    CounterKind::Loss
                } else {
                    CounterKind::Error
                },
            });
        }
    }
    d
}
fn cleanup(session: Session, initial: &str, resources: (usize, usize), marker: &str) -> Result<()> {
    drop(session);
    let after = snapshot()?;
    sys::sleep_ms(10)?;
    let settled = snapshot()?;
    let current = sys::resources();
    let a = totals(initial);
    let b = totals(&settled);
    let sa = system_counts(initial)?;
    let sb = system_counts(&after)?;
    let sc = system_counts(&settled)?;
    // Registry/subscriber values are explicitly system-scoped. An isolated
    // acceptance VM can require equality; concurrent independent recorders may
    // legitimately change them, so production reports rather than fabricates
    // per-session ownership from these totals.
    log(&format!(
        "{marker} fds_before={} fds_after={} mapped_before={} mapped_after={} events_before={} \
         events_after={} programs_before={} programs_after={} registered_before={} \
         registered_after={} registered_settled={} subscriptions_before={} subscriptions_after={} \
         subscriptions_settled={} enabled=0",
        resources.0,
        current.0,
        resources.1,
        current.1,
        a.0,
        b.0,
        a.1,
        b.1,
        sa.0,
        sb.0,
        sc.0,
        sa.1,
        sb.1,
        sc.1
    ));
    Ok(())
}
fn phase_stats(phase: &str, point: &str) -> Result<()> {
    let stats = snapshot()?;
    sys::print(&format!(
        "RECORD_STATS BEGIN phase={phase} point={point} bytes={}\n",
        stats.len()
    ));
    sys::print(&stats);
    sys::print(&format!("RECORD_STATS END phase={phase} point={point}\n"));
    Ok(())
}
fn record(plan: &SessionPlan, hooks: &Hooks) -> Result<()> {
    let _signals = Signals::new()?;
    // Read the explicit input before opening/truncating the output. The guest
    // later compares its GNU note to the actual boot note, never its filename.
    let kernel_elf = plan
        .options
        .kernel_elf
        .as_deref()
        .map(|path| sys::read_bytes(path, KERNEL_ELF_READ_LIMIT))
        .transpose()?;
    let output = Fd::open(&plan.options.output, true)?;
    let initial = snapshot()?;
    system_counts(&initial)?;
    let resources = sys::resources();
    let mut session = Session::new();
    if let Err(error) = session.prepare(plan, hooks) {
        cleanup(session, &initial, resources, "ROLLBACK")?;
        return Err(error);
    }
    let observation = match mapping_snapshot(hooks.fail_snapshot)
        .and_then(|journal| Observation::begin(journal, kernel_elf.as_deref()))
    {
        Ok(observation) => observation,
        Err(error) => {
            cleanup(session, &initial, resources, "ROLLBACK")?;
            return Err(error);
        }
    };
    drop(kernel_elf);
    log(&format!(
        "OBSERVATION initial_snapshot_ns={} kernel_build_id={} kernel_sha256={}",
        observation.initial_snapshot_ns(),
        observation.kernel_build_id().unwrap_or("unknown"),
        observation.kernel_sha256().unwrap_or("unknown")
    ));
    if hooks.detached_ms != 0 {
        phase_stats("loaded_detached", "before")?;
        log(&format!(
            "DETACHED start_ns={} duration_ms={}",
            sys::now()?,
            hooks.detached_ms
        ));
        sys::sleep_ms(hooks.detached_ms)?;
        log(&format!("DETACHED_END stop_ns={}", sys::now()?));
        phase_stats("loaded_detached", "after")?;
        cleanup(session, &initial, resources, "CLEANUP")?;
        return Ok(());
    }
    if hooks.dup_close {
        session.duplicate_sources()?;
    }
    let before = snapshot()?;
    let first = session.sources.first().ok_or("empty source set")?;
    let mut writer = CaptureWriter::new(
        SessionConfig {
            pulse_commit: "unknown".into(),
            target_arch: if cfg!(target_arch = "riscv64") {
                CaptureArch::Riscv64
            } else {
                CaptureArch::LoongArch64
            },
            kernel_elf_path: plan
                .options
                .kernel_elf
                .clone()
                .unwrap_or_else(|| "unknown".into()),
            kernel_elf_hash: observation.kernel_sha256().unwrap_or("unknown").into(),
            image_path: "unknown".into(),
            image_hash: "unknown".into(),
            libbpf_fixture_version: "pulse-native-recorder-v1".into(),
            prog_id: first.binding.program_id,
            map_id: session.output_map_id,
            link_id: first.binding.link_id,
            perf_event_id: 0,
            output_path: plan.options.output.clone(),
            scope: first.binding.scope,
            sample_period: plan.period_ns,
            buffer_pages: plan.options.buffer_pages as u64,
            clock_name: "monotonic".into(),
            clock_res_ns: 1,
        },
        SchemaRegistry::default_pulse_registry(),
    );
    writer
        .configure_recorder(
            session.sources.iter().map(|s| s.binding.clone()).collect(),
            plan.options.record_bytes,
        )
        .map_err(|e| format!("capture sources: {e:?}"))?;
    let start = sys::now()?;
    writer
        .start(start)
        .map_err(|e| format!("capture start: {e:?}"))?;
    let mut records = 0;
    let mut lost = 0;
    let mut capture_error = None;
    let mut control_errors = ControlErrors::default();
    let enabled = control_errors.observe(session.enable()).is_some();
    let mut last_target_probe = start;
    let reason = loop {
        if !enabled {
            break "control-error".into();
        }
        if let Err(error) = session.drain(&mut writer, &mut records, &mut lost, 8) {
            capture_error = Some(error);
            break "consumer-error".into();
        }
        match control_errors.observe(_signals.poll()) {
            Some(Some(signal)) => break format!("signal:{signal}"),
            Some(None) => {}
            None => break "control-error".into(),
        }
        let Some(now) = control_errors.observe(sys::now()) else {
            break "control-error".into();
        };
        if plan.options.tid.is_some() && now.saturating_sub(last_target_probe) >= 10_000_000 {
            last_target_probe = now;
            match control_errors.observe(session.target_alive()) {
                Some(false) => break "target-exit".into(),
                Some(true) => {}
                None => break "control-error".into(),
            }
        }
        if plan
            .duration_ns
            .is_some_and(|duration| now.saturating_sub(start) >= duration)
        {
            break "duration".into();
        }
        if control_errors.observe(sys::sleep_ms(1)).is_none() {
            break "control-error".into();
        }
    };
    if hooks.stop_failure {
        // Exercise an actual failing control syscall. The regular output FD is
        // not a perf source; recovery still disables every real source.
        match output.enable(false) {
            Err(error) => {
                log(&format!("STOP_FAILURE actual_error={error}"));
                control_errors.record(error);
            }
            Ok(()) => control_errors.record("stop-failure injection unexpectedly succeeded".into()),
        }
    }
    let quiescent = session.disable(&mut control_errors);
    if quiescent {
        if let Err(error) = session.drain(&mut writer, &mut records, &mut lost, usize::MAX) {
            capture_error = Some(error);
        }
    }
    if quiescent && capture_error.is_none() {
        let stopped = session.sources.iter().map(|s| s.raw_samples).sum::<u64>();
        control_errors.observe(sys::sleep_ms(10));
        if let Err(error) = session.drain(&mut writer, &mut records, &mut lost, usize::MAX) {
            capture_error = Some(error);
        }
        let after = session.sources.iter().map(|s| s.raw_samples).sum::<u64>();
        log(&format!("NO_GROWTH before={stopped} after={after}"));
        if stopped != after {
            capture_error = Some("source emitted after quiescence".into());
        }
    }
    let stop = control_errors.observe(sys::now());
    let after = control_errors.observe(snapshot()).unwrap_or_default();
    // All source disable attempts and the final drain precede this proc-open
    // cut. On read failure Observation keeps the original pre-enable journal
    // and an explicitly unknown final mapping boundary.
    let observation = observation.finish(mapping_snapshot(hooks.fail_journal));
    for error in observation.errors {
        control_errors.record(error);
    }
    log(&format!(
        "MAPPINGS bytes={} artifacts={}",
        observation.mappings.journal.len(),
        observation.mappings.artifacts.len()
    ));
    if let Err(error) = writer.set_mappings(observation.mappings) {
        control_errors.record(format!("capture mappings: {error:?}"));
    }
    for source in &session.sources {
        writer
            .update_recorder_source(source.binding.clone())
            .map_err(|e| format!("capture window: {e:?}"))?;
    }
    let mut diagnostic = diagnostics(plan, &session, &before, &after, &reason, records);
    diagnostic
        .identities
        .extend(observation.diagnostics.identities);
    diagnostic.counters.extend(observation.diagnostics.counters);
    let heap = sys::heap_resources();
    for (name, value) in [
        ("heap_reserved_bytes", heap.reserved_bytes),
        ("heap_used_before_serialization_bytes", heap.used_bytes),
        (
            "heap_peak_before_serialization_bytes",
            heap.peak_allocated_bytes,
        ),
    ] {
        diagnostic.counters.push(DiagnosticCounter {
            name: name.into(),
            scope: "recorder_process".into(),
            value: Some(value as u64),
            kind: CounterKind::Activity,
        });
    }
    diagnostic.counters.push(DiagnosticCounter {
        name: "control_errors".into(),
        scope: "session".into(),
        value: Some(control_errors.count),
        kind: CounterKind::Error,
    });
    diagnostic.counters.push(DiagnosticCounter {
        name: "quiescent_sources".into(),
        scope: "session".into(),
        value: if quiescent {
            Some(session.sources.len() as u64)
        } else {
            None
        },
        kind: CounterKind::Activity,
    });
    if let Some(error) = &control_errors.first {
        diagnostic.identities.push(DiagnosticIdentity {
            name: "control_error".into(),
            value: Some(error.clone()),
        });
    }
    diagnostic.counters.push(DiagnosticCounter {
        name: "consumer_errors".into(),
        scope: "consumer".into(),
        value: Some(u64::from(capture_error.is_some())),
        kind: CounterKind::Error,
    });
    if let Some(error) = &capture_error {
        diagnostic.identities.push(DiagnosticIdentity {
            name: "consumer_error".into(),
            value: Some(error.clone()),
        });
    }
    writer
        .set_diagnostics(diagnostic)
        .map_err(|e| format!("capture diagnostics: {e:?}"))?;
    let boundary_known = quiescent
        && stop.is_some()
        && session.sources.iter().all(|source| {
            source.binding.enable_after_ns != 0 && source.binding.disable_after_ns != 0
        });
    let bytes = if boundary_known {
        match writer.finish(stop.unwrap()) {
            Ok(bytes) => bytes,
            Err(error) => {
                control_errors.record(format!("capture finish: {error:?}"));
                writer
                    .abort_partial_bytes()
                    .map_err(|e| format!("partial capture: {e:?}"))?
            }
        }
    } else {
        log("PARTIAL boundary=unknown trailer=absent");
        writer
            .abort_partial_bytes()
            .map_err(|e| format!("partial capture: {e:?}"))?
    };
    log(&format!(
        "STOP reason={reason} records={records} lost={lost} bytes={} partial=1",
        bytes.len()
    ));
    let write_result = if let Some(limit) = hooks.write_fail_after {
        output.write_all(&bytes[..limit.min(bytes.len().saturating_sub(1))])?;
        // Acceptance drives a real failed write through a read-only descriptor;
        // the original output retains its actually written incomplete prefix.
        let read_only = Fd::open(&plan.options.output, false)?;
        read_only.write_all(b"injected write failure")
    } else {
        output.write_all(&bytes).and_then(|_| output.sync())
    };
    cleanup(session, &initial, resources, "CLEANUP")?;
    write_result?;
    log_heap("saved");
    log(&format!(
        "SAVED output={} bytes={} sha256={:x}",
        plan.options.output,
        bytes.len(),
        Sha256::digest(&bytes),
    ));
    if let Some(error) = capture_error {
        return Err(error);
    }
    if let Some(error) = control_errors.first {
        return Err(error);
    }
    Ok(())
}
pub fn run(args: &[&str]) -> Result<()> {
    if args == ["--help"] {
        sys::print(
            "bpf-record --events cpu|task|sched|fault[,..] --output FILE [--tid TID] [--cpus \
             all|LIST] [--duration-ms N] [--period-ns N|--frequency HZ] [--buffer-pages N] \
             [--record-bytes N] [--callchain fp|none] [--stack-depth 32] [--stack-bytes 512] \
             [--kernel-elf FILE] [--allow-fallback]\nSIGINT/SIGTERM stop, quiesce and save. \
             Targets are existing tasks; recorder never launches a workload.\n",
        );
        return Ok(());
    }
    let (options, hooks) = parse(args)?;
    let stats = snapshot()?;
    let plan = SessionPlan::new(options, Capabilities::from_stats(&stats)?)?;
    if let Some(tid) = plan.options.tid {
        if !sys::target_exists(tid)? {
            return Err("target TID does not exist".into());
        }
    }
    log(&format!("CONFIG {}", plan.evidence()));
    record(&plan, &hooks)
}
