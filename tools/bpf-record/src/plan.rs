use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use bpf_capture::recorder::{RecorderKind, SourceConfig};
use pulse_bpf_schema::{DEFAULT_STACK_BYTE_LIMIT, DEFAULT_STACK_DEPTH, PerfStackSampleContext};

const MAX_SOURCES: usize = 128;
const MAX_MAPPED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SCRATCH_BYTES: u64 = 8 * 1024 * 1024;

/// Capabilities observed from the kernel's stable per-open diagnostics snapshot.
#[derive(Clone, Debug)]
pub struct Capabilities {
    pub online_mask: u64,
    pub cpu_clock: bool,
    pub task_clock: bool,
    pub sched: bool,
    pub fault: bool,
    pub min_period_ns: u64,
    pub stack_context_version: u64,
    pub stack_depth: u64,
    pub stack_bytes: u64,
}

impl Capabilities {
    pub fn from_stats(text: &str) -> Result<Self, String> {
        let line = text.lines().next().ok_or("missing capabilities")?;
        if !line.starts_with("PULSE_BPF_STATS ")
            || !text.lines().last().is_some_and(|l| l.starts_with("END "))
        {
            return Err("incomplete capability snapshot".into());
        }
        let field = |name: &str| -> Result<u64, String> {
            let mut values = line
                .split_whitespace()
                .filter_map(|s| s.split_once('='))
                .filter(|(k, _)| *k == name);
            let value = values
                .next()
                .ok_or_else(|| format!("missing capability {name}"))?
                .1;
            if values.next().is_some() {
                return Err(format!("duplicate capability {name}"));
            }
            value
                .parse()
                .map_err(|_| format!("invalid capability {name}"))
        };
        if field("version")? != 1 || field("available")? != 1 || field("capabilities_version")? != 1
        {
            return Err("sampling capabilities unavailable or unsupported".into());
        }
        let flag = |name| match field(name)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(format!("invalid capability {name}")),
        };
        let caps = Self {
            online_mask: field("online_mask")?,
            cpu_clock: flag("cpu_clock")?,
            task_clock: flag("task_clock")?,
            sched: flag("sched")?,
            fault: flag("fault")?,
            min_period_ns: field("min_period_ns")?,
            stack_context_version: field("stack_context_version")?,
            stack_depth: field("stack_depth")?,
            stack_bytes: field("stack_bytes")?,
        };
        caps.validate()?;
        Ok(caps)
    }
    fn validate(&self) -> Result<(), String> {
        if self.online_mask == 0 || self.min_period_ns == 0 {
            return Err("empty sampling capabilities".into());
        }
        match (
            self.stack_context_version,
            self.stack_depth,
            self.stack_bytes,
        ) {
            (0, 0, 0) => Ok(()),
            (3, depth, bytes)
                if depth == u64::from(DEFAULT_STACK_DEPTH)
                    && bytes == u64::from(DEFAULT_STACK_BYTE_LIMIT) =>
            {
                Ok(())
            }
            _ => Err("invalid or unsupported stack capability geometry".into()),
        }
    }
    pub fn online_cpus(&self) -> Vec<u32> {
        (0..64)
            .filter(|cpu| self.online_mask & (1u64 << cpu) != 0)
            .collect()
    }
}

/// The requested privilege domain is always that of the interrupted sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Callchain {
    None,
    FramePointer,
}
impl Callchain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FramePointer => "fp",
        }
    }
}

/// A tracepoint event is expanded from the complete scheduler group by the plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Cpu,
    Task,
    Sched(u32),
    Fault,
}
impl Event {
    pub fn source_config(self) -> SourceConfig {
        match self {
            Self::Cpu => SourceConfig::CpuClock,
            Self::Task => SourceConfig::TaskClock,
            Self::Sched(_) | Self::Fault => SourceConfig::Tracepoint,
        }
    }
    pub fn is_software(self) -> bool {
        matches!(self, Self::Cpu | Self::Task)
    }
    pub fn perf_type(self) -> u32 {
        if self.is_software() { 1 } else { 2 }
    }
    pub fn config(self) -> u64 {
        match self {
            Self::Cpu => 0,
            Self::Task => 1,
            Self::Sched(id) => id as u64,
            Self::Fault => 8,
        }
    }
    pub fn context_size(self) -> usize {
        match self {
            Self::Cpu | Self::Task => 64,
            // Invalid public Event::Sched values cannot generate a program:
            // only the supported registry's exact context geometry is accepted.
            _ => pulse_bpf_schema::lookup_by_id(self.config() as u32)
                .map_or(0, |schema| schema.context_size),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub events: Vec<String>,
    pub cpus: Option<String>,
    pub tid: Option<u32>,
    pub duration_ms: Option<u64>,
    pub period_ns: Option<u64>,
    pub frequency: Option<u64>,
    pub buffer_pages: usize,
    pub record_bytes: usize,
    pub output: String,
    pub allow_fallback: bool,
    /// None selects frame pointers for software sources, no chain for traces.
    pub callchain: Option<Callchain>,
    pub stack_depth: Option<u64>,
    pub stack_bytes: Option<u64>,
    pub kernel_elf: Option<String>,
}

impl Options {
    /// Parse the actual CLI arguments, excluding argv[0]. No source is opened here.
    pub fn parse(args: &[&str]) -> Result<Self, String> {
        let mut result = Self {
            events: Vec::new(),
            cpus: None,
            tid: None,
            duration_ms: None,
            period_ns: None,
            frequency: None,
            buffer_pages: 16,
            record_bytes: 8 * 1024 * 1024,
            output: String::new(),
            allow_fallback: false,
            callchain: None,
            stack_depth: None,
            stack_bytes: None,
            kernel_elf: None,
        };
        let mut seen = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let key = args[i];
            if seen.contains(&key) && key != "--events" {
                return Err(format!("duplicate option {key}"));
            }
            seen.push(key);
            if key == "--allow-fallback" {
                result.allow_fallback = true;
                i += 1;
                continue;
            }
            let value = args
                .get(i + 1)
                .ok_or_else(|| format!("missing value for {key}"))?;
            let number = || {
                value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid number for {key}"))
            };
            match key {
                "--events" => result
                    .events
                    .extend(value.split(',').map(ToString::to_string)),
                "--cpus" => result.cpus = Some(value.to_string()),
                "--tid" => {
                    result.tid = Some(u32::try_from(number()?).map_err(|_| "TID out of range")?)
                }
                "--duration-ms" => result.duration_ms = Some(number()?),
                "--period-ns" => result.period_ns = Some(number()?),
                "--frequency" => result.frequency = Some(number()?),
                "--buffer-pages" => {
                    result.buffer_pages =
                        usize::try_from(number()?).map_err(|_| "buffer size overflow")?
                }
                "--record-bytes" => {
                    result.record_bytes =
                        usize::try_from(number()?).map_err(|_| "record size overflow")?
                }
                "--output" => result.output = value.to_string(),
                "--callchain" => {
                    result.callchain = Some(match *value {
                        "none" => Callchain::None,
                        "fp" => Callchain::FramePointer,
                        _ => return Err("callchain must be none or fp".into()),
                    })
                }
                "--stack-depth" => result.stack_depth = Some(number()?),
                "--stack-bytes" => result.stack_bytes = Some(number()?),
                "--kernel-elf" => result.kernel_elf = Some(value.to_string()),
                _ => return Err(format!("unsupported option {key}")),
            }
            i += 2;
        }
        if result.events.is_empty() || result.output.is_empty() || result.output.contains('\0') {
            return Err("--events and --output are required".into());
        }
        if result
            .kernel_elf
            .as_ref()
            .is_some_and(|path| path.is_empty() || path.contains('\0'))
        {
            return Err("kernel-elf requires a nonempty path without NUL".into());
        }
        Ok(result)
    }
}

#[derive(Clone, Debug)]
pub struct SourcePlan {
    pub id: u32,
    pub event: Event,
    /// Requested mode before an explicitly permitted capability fallback.
    pub requested_config: SourceConfig,
    pub cpu: Option<u32>,
    pub tid: Option<u32>,
    pub period_ns: u64,
    pub kind: RecorderKind,
}
struct ContextLayout {
    event_id: u32,
    bytes: usize,
    schema_version: u32,
}
impl SourcePlan {
    fn context_layout(&self) -> ContextLayout {
        match self.kind {
            RecorderKind::SoftwareStackV3 => ContextLayout {
                event_id: bpf_capture::schema::PERF_EVENT_SOFTWARE_STACK_V3_ID,
                bytes: PerfStackSampleContext::SIZE,
                schema_version: 3,
            },
            RecorderKind::SoftwareV2 => ContextLayout {
                event_id: bpf_capture::schema::PERF_EVENT_SOFTWARE_V2_ID,
                bytes: 64,
                schema_version: 2,
            },
            RecorderKind::Tracepoint | RecorderKind::Normalized => ContextLayout {
                event_id: self.event.config() as u32,
                bytes: if self.kind == RecorderKind::Tracepoint {
                    self.event.context_size()
                } else {
                    0
                },
                schema_version: 1,
            },
        }
    }
    pub fn event_id(&self) -> u32 {
        self.context_layout().event_id
    }
    pub fn context_size(&self) -> usize {
        self.context_layout().bytes
    }
    pub fn schema_version(&self) -> u32 {
        self.context_layout().schema_version
    }
}

#[derive(Clone, Debug)]
pub struct SessionPlan {
    pub options: Options,
    pub cpus: Vec<u32>,
    pub sink_cpus: Vec<u32>,
    pub sources: Vec<SourcePlan>,
    pub period_ns: u64,
    pub duration_ns: Option<u64>,
    /// Ring mappings only; excludes bounded capture storage and kernel objects.
    pub mapped_bytes: u64,
    /// Initialized source-map values, excluding allocator/map bookkeeping.
    pub scratch_bytes: u64,
    pub fallback: Option<String>,
    pub requested_callchain: Callchain,
    pub effective_callchain: Callchain,
    pub stack_depth: u64,
    pub stack_bytes: u64,
}

impl SessionPlan {
    pub fn new(options: Options, caps: Capabilities) -> Result<Self, String> {
        caps.validate()?;
        if options.kernel_elf.as_ref() == Some(&options.output) {
            return Err("output must differ from kernel-elf".into());
        }
        if options.events.is_empty()
            || options.output.is_empty()
            || options.output.contains('\0')
            || caps.min_period_ns == 0
            || options
                .kernel_elf
                .as_ref()
                .is_some_and(|path| path.is_empty() || path.contains('\0'))
        {
            return Err("empty event plan, invalid output, or invalid capabilities".into());
        }
        if options.period_ns.is_some() && options.frequency.is_some() {
            return Err("period and frequency are mutually exclusive".into());
        }
        let period_ns = match (options.period_ns, options.frequency) {
            (Some(0), _) | (_, Some(0)) => return Err("period/frequency must be nonzero".into()),
            (_, Some(hz)) if hz > 1_000_000_000 => {
                return Err("frequency exceeds nanosecond resolution".into());
            }
            (_, Some(hz)) => 1_000_000_000u64.div_ceil(hz),
            (Some(ns), _) => ns,
            _ => 10_000_000,
        };
        if period_ns < caps.min_period_ns {
            return Err("period below probed minimum".into());
        }
        let duration_ns = options
            .duration_ms
            .map(|ms| {
                ms.checked_mul(1_000_000)
                    .filter(|n| *n != 0)
                    .ok_or("invalid duration")
            })
            .transpose()?;
        if !options.buffer_pages.is_power_of_two()
            || options.buffer_pages > 256
            || !(4096..=64 * 1024 * 1024).contains(&options.record_bytes)
        {
            return Err(
                "buffer-pages must be a power of two <=256; record-bytes must be 4096..67108864"
                    .into(),
            );
        }
        let online = caps.online_cpus();
        if online.is_empty() {
            return Err("no online CPUs".into());
        }
        let mut cpus = match options.cpus.as_deref().unwrap_or("all") {
            "all" => online.clone(),
            list => {
                let mut cpus = Vec::new();
                for item in list.split(',') {
                    let cpu: u32 = item.parse().map_err(|_| "invalid CPU list")?;
                    if !online.contains(&cpu) || cpus.contains(&cpu) {
                        return Err("offline or duplicate CPU".into());
                    }
                    cpus.push(cpu);
                }
                cpus
            }
        };
        cpus.sort_unstable();
        let mut events = Vec::new();
        let mut fallback = None;
        for name in &options.events {
            match name.as_str() {
                "cpu" if caps.cpu_clock => events.push((Event::Cpu, SourceConfig::CpuClock)),
                "task" if caps.task_clock => events.push((Event::Task, SourceConfig::TaskClock)),
                "sched" if caps.sched => {
                    events.extend((1..=6).map(|id| (Event::Sched(id), SourceConfig::Tracepoint)))
                }
                "fault" if caps.fault => events.push((Event::Fault, SourceConfig::Tracepoint)),
                "cycles" if options.allow_fallback && caps.cpu_clock => {
                    events.push((Event::Cpu, SourceConfig::HardwareCycles));
                    fallback = Some(
                        "hardware-cycles unavailable; explicit fallback to cpu-clock nanoseconds"
                            .into(),
                    );
                }
                _ => return Err(format!("unsupported or unavailable event {name}")),
            }
        }
        let task = events.iter().any(|(event, _)| *event == Event::Task);
        let software = events.iter().any(|(event, _)| event.is_software());
        let requested_callchain = options.callchain.unwrap_or(if software {
            Callchain::FramePointer
        } else {
            Callchain::None
        });
        if requested_callchain == Callchain::FramePointer && !software {
            return Err(
                "frame-pointer callchains require a software source; tracepoint stacks unsupported"
                    .into(),
            );
        }
        if requested_callchain == Callchain::None
            && (options.stack_depth.is_some() || options.stack_bytes.is_some())
        {
            return Err("stack limits require frame-pointer callchains".into());
        }
        let requested_depth = options
            .stack_depth
            .unwrap_or(u64::from(DEFAULT_STACK_DEPTH));
        let requested_bytes = options
            .stack_bytes
            .unwrap_or(u64::from(DEFAULT_STACK_BYTE_LIMIT));
        if requested_callchain == Callchain::FramePointer
            && (requested_depth != u64::from(DEFAULT_STACK_DEPTH)
                || requested_bytes != u64::from(DEFAULT_STACK_BYTE_LIMIT))
        {
            return Err("kernel frame-pointer capture supports only depth=32 and bytes=512".into());
        }
        let supported = caps.stack_context_version == 3
            && caps.stack_depth == requested_depth
            && caps.stack_bytes == requested_bytes;
        let effective_callchain = if requested_callchain == Callchain::FramePointer && !supported {
            if !options.allow_fallback {
                return Err("requested frame-pointer capability unavailable".into());
            }
            let reason = "frame-pointer unavailable; explicit fallback to no callchain";
            fallback = Some(match fallback {
                Some(previous) => format!("{previous}; {reason}"),
                None => reason.into(),
            });
            Callchain::None
        } else {
            requested_callchain
        };
        let (stack_depth, stack_bytes) = if effective_callchain == Callchain::FramePointer {
            (requested_depth, requested_bytes)
        } else {
            (0, 0)
        };
        if task
            && (options.tid.is_none()
                || options.tid == Some(0)
                || options.tid.is_some_and(|n| n > i32::MAX as u32))
        {
            return Err("task requires an explicit positive --tid".into());
        }
        if !task && options.tid.is_some() {
            return Err("--tid applies only to task-clock; trace filtering is unsupported".into());
        }
        if task && cpus != online {
            return Err(
                "task-clock requires all online CPU sinks; CPU affinity filtering unsupported"
                    .into(),
            );
        }
        if !events.iter().any(|(event, _)| event.is_software())
            && (options.period_ns.is_some() || options.frequency.is_some())
        {
            return Err("tracepoints are event-driven and do not accept period/frequency".into());
        }
        let sink_cpus = if task { online } else { cpus.clone() };
        let mapped_bytes = (options.buffer_pages as u64 + 1) * 4096 * sink_cpus.len() as u64;
        if mapped_bytes > MAX_MAPPED_BYTES {
            return Err("session ring budget exceeds 64 MiB".into());
        }
        let mut sources = Vec::new();
        for (event, requested_config) in events {
            let targets: Vec<Option<u32>> = if event == Event::Task {
                alloc::vec![None]
            } else {
                cpus.iter().copied().map(Some).collect()
            };
            for cpu in targets {
                if sources.len() == MAX_SOURCES {
                    return Err("session exceeds 128 sources".into());
                }
                sources.push(SourcePlan {
                    id: sources.len() as u32 + 1,
                    event,
                    requested_config,
                    cpu,
                    tid: if event == Event::Task {
                        options.tid
                    } else {
                        None
                    },
                    period_ns: if event.is_software() { period_ns } else { 1 },
                    kind: if !event.is_software() {
                        RecorderKind::Tracepoint
                    } else if effective_callchain == Callchain::FramePointer {
                        RecorderKind::SoftwareStackV3
                    } else {
                        RecorderKind::SoftwareV2
                    },
                });
            }
        }
        let slots = u64::from(sink_cpus.iter().copied().max().ok_or("no output CPUs")?) + 1;
        let scratch_bytes: u64 = sources
            .iter()
            .map(|source| (24 + source.context_size()) as u64 * slots)
            .sum();
        if scratch_bytes > MAX_SCRATCH_BYTES {
            return Err("session source-map values exceed 8 MiB".into());
        }
        Ok(Self {
            options,
            cpus,
            sink_cpus,
            sources,
            period_ns,
            duration_ns,
            mapped_bytes,
            scratch_bytes,
            fallback,
            requested_callchain,
            effective_callchain,
            stack_depth,
            stack_bytes,
        })
    }

    pub fn evidence(&self) -> String {
        format!(
            "plan_version=1 requested_events={} requested_cpus={} expanded_cpus={:?} \
             requested_tid={} requested_period_ns={} requested_frequency={} \
             effective_period_ns={} frequency_conversion=ceil_ns effective_events={:?} \
             fallback={} duration_ms={} buffer_pages={} record_bytes={} requested_callchain={} \
             effective_callchain={} requested_stack_depth={} requested_stack_bytes={} \
             effective_stack_depth={} effective_stack_bytes={} scratch_map_bytes={}",
            self.options.events.join(","),
            self.options.cpus.as_deref().unwrap_or("all"),
            self.cpus,
            self.options
                .tid
                .map_or_else(|| "none".into(), |n| n.to_string()),
            self.options
                .period_ns
                .map_or_else(|| "none".into(), |n| n.to_string()),
            self.options
                .frequency
                .map_or_else(|| "none".into(), |n| n.to_string()),
            self.period_ns,
            self.sources.iter().map(|s| s.event).collect::<Vec<_>>(),
            self.fallback.as_deref().unwrap_or("none"),
            self.options
                .duration_ms
                .map_or_else(|| "signal_or_target_exit".into(), |n| n.to_string()),
            self.options.buffer_pages,
            self.options.record_bytes,
            self.requested_callchain.as_str(),
            self.effective_callchain.as_str(),
            self.options
                .stack_depth
                .map_or_else(|| "default".into(), |n| n.to_string()),
            self.options
                .stack_bytes
                .map_or_else(|| "default".into(), |n| n.to_string()),
            self.stack_depth,
            self.stack_bytes,
            self.scratch_bytes,
        )
    }
}
