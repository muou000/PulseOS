//! Time-valid association is conservative at producer transactions, timestamp
//! ties, loss, and outside the journal cut. It never reads host process maps.
use bpf_capture::mapping::{
    Mapping, MappingEvent, MappingJournal, MappingMetadata, MutationTarget, TaskClass,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedMapping {
    pub task: u64,
    pub space: u64,
    pub exec: u64,
    pub class: TaskClass,
    pub comm: String,
    pub mapping: Mapping,
    pub file_offset: u64,
    pub sha256: Option<String>,
    pub path: String,
}
#[derive(Clone, Debug)]
pub struct MappingTimeline {
    journal: MappingJournal,
}
impl MappingTimeline {
    pub fn new(metadata: &MappingMetadata) -> Result<Self, String> {
        metadata
            .validate()
            .map_err(|e| format!("invalid mapping metadata: {e:?}"))?;
        Ok(Self {
            journal: MappingJournal::parse(&metadata.journal)
                .map_err(|e| format!("invalid mapping journal: {e:?}"))?,
        })
    }
    pub fn journal(&self) -> &MappingJournal {
        &self.journal
    }
    // Begin records are published before the producer changes any state. Unlike
    // retrospective snapshot intervals, they survive a cut while a lease is live.
    fn check_mutations(
        &self,
        target: MutationTarget,
        id: u64,
        time: u64,
    ) -> Result<(), &'static str> {
        let mut pending = std::collections::BTreeMap::new();
        let mut seen = std::collections::BTreeSet::new();
        for entry in &self.journal.entries {
            if let MappingEvent::Mutation {
                target: entry_target,
                id: entry_id,
                token,
                complete,
            } = entry.event
            {
                if entry_target != target || entry_id != id {
                    continue;
                }
                if !complete {
                    if !seen.insert(token) {
                        return Err("mutation token reused");
                    }
                    pending.insert(token, entry.timestamp_ns);
                } else if let Some(begin) = pending.remove(&token) {
                    if begin <= time && time <= entry.timestamp_ns {
                        return Err("mutation interval in progress");
                    }
                } else {
                    return Err("mutation completion without begin");
                }
            }
        }
        if pending.values().any(|begin| *begin <= time) {
            return Err("mutation incomplete at journal cut");
        }
        Ok(())
    }
    pub fn lookup(
        &self,
        task: u64,
        pid: u32,
        tid: u32,
        time: u64,
        ip: u64,
    ) -> Result<ResolvedMapping, &'static str> {
        if self.journal.dropped != 0 {
            return Err("mapping journal loss");
        }
        if time < self.journal.started_ns || time >= self.journal.snapshot_ns {
            return Err("outside mapping coverage");
        }
        self.check_mutations(MutationTarget::Task, task, time)?;
        let mut identity: Option<(u32, u32, u64, u64, TaskClass, &str)> = None;
        for entry in &self.journal.entries {
            if let MappingEvent::Task {
                task: target,
                begin_ns,
                ..
            } = &entry.event
            {
                if *target == task && *begin_ns <= time && time <= entry.timestamp_ns {
                    return Err("task transition in progress or timestamp tie");
                }
            }
        }
        let mut dead = false;
        for entry in &self.journal.entries {
            if let MappingEvent::Task {
                task: target,
                pid: record_pid,
                tid: record_tid,
                space,
                exec,
                kind,
                class,
                comm,
                ..
            } = &entry.event
            {
                if *target != task || entry.timestamp_ns > time {
                    continue;
                }
                if entry.timestamp_ns == time {
                    return Err("task transition timestamp tie");
                }
                if kind == "exit" {
                    dead = true;
                    identity = None;
                    continue;
                }
                if dead {
                    return Err("reused stable task identity");
                }
                if let Some((old_pid, old_tid, old_space, old_exec, ..)) = identity {
                    if old_pid != *record_pid
                        || (old_tid != *record_tid && kind != "exec")
                        || *exec < old_exec
                        || (kind == "exec" && (*exec <= old_exec || *space == old_space))
                        || matches!(kind.as_str(), "bind" | "fork")
                        || (kind != "exec" && (*space != old_space || *exec != old_exec))
                    {
                        return Err("inconsistent stable task identity");
                    }
                }
                identity = Some((
                    *record_pid,
                    *record_tid,
                    *space,
                    *exec,
                    *class,
                    comm.as_str(),
                ));
            }
        }
        let (record_pid, record_tid, space, exec, class, comm) =
            identity.ok_or("task identity unavailable")?;
        if pid != record_pid || tid != record_tid {
            return Err("sample task identity mismatch");
        }
        if class != TaskClass::User || space == 0 {
            return Err("user address space unavailable");
        }
        self.check_mutations(MutationTarget::Space, space, time)?;
        let mut pending = std::collections::BTreeMap::new();
        let mut seen_tokens = std::collections::BTreeSet::new();
        for entry in &self.journal.entries {
            if let MappingEvent::Tlb {
                space: target,
                token,
                complete,
            } = &entry.event
            {
                if *target != space {
                    continue;
                }
                if !complete {
                    if !seen_tokens.insert(*token)
                        || pending.insert(*token, entry.timestamp_ns).is_some()
                    {
                        return Err("duplicate TLB token");
                    }
                } else if let Some(begin) = pending.remove(token) {
                    if begin <= time && time <= entry.timestamp_ns {
                        return Err("TLB publication in progress");
                    }
                } else {
                    return Err("TLB completion without begin");
                }
            }
        }
        if pending.values().any(|begin| *begin <= time) {
            return Err("TLB publication incomplete");
        }
        let mut latest = None;
        let mut revision = None;
        for entry in &self.journal.entries {
            if let MappingEvent::Space {
                space: target,
                begin_ns,
                maps,
                revision: current,
            } = &entry.event
            {
                if *target != space {
                    continue;
                }
                if revision.is_some_and(|r| *current <= r) {
                    return Err("address space revision reused or regressed");
                }
                revision = Some(*current);
                if *begin_ns <= time && time <= entry.timestamp_ns {
                    return Err("mapping mutation in progress or timestamp tie");
                }
                if entry.timestamp_ns < time {
                    latest = Some(maps);
                }
            }
        }
        let maps = latest.ok_or("initial mapping snapshot unavailable")?;
        let mapping = maps
            .iter()
            .find(|m| ip >= m.start && ip - m.start < m.len)
            .ok_or("address unmapped")?;
        if mapping.permissions & 4 == 0 {
            return Err("mapping is not executable");
        }
        let file_offset = mapping
            .pgoff
            .checked_add(ip - mapping.start)
            .ok_or("file offset overflow")?;
        let mut object = None;
        for entry in &self.journal.entries {
            if let MappingEvent::Object {
                object: id,
                sha256,
                path,
            } = &entry.event
            {
                if *id != mapping.object || entry.timestamp_ns > time {
                    continue;
                }
                if entry.timestamp_ns == time {
                    return Err("object timestamp tie");
                }
                if object.is_some() {
                    return Err("object identity reused");
                }
                object = Some((sha256.clone(), path.clone()));
            }
        }
        let (sha256, path) = object.unwrap_or_default();
        Ok(ResolvedMapping {
            task,
            space,
            exec,
            class,
            comm: comm.into(),
            mapping: mapping.clone(),
            file_offset,
            sha256,
            path,
        })
    }
}

/// Machine-readable association report. A mapped IP and a verified ELF are
/// separate facts; unknown symbols do not erase the captured mapping identity.
pub fn render_report(
    analyzer: &crate::CaptureAnalyzer,
    events: &[crate::NormalizedEvent],
    bundle: Option<&std::path::Path>,
) -> String {
    use std::collections::BTreeMap;

    use crate::{artifact::VerifiedElf, emission::json_string as quote, event::EventPayload};
    let metadata = analyzer.data().mappings.as_ref();
    let timeline = metadata.and_then(|m| MappingTimeline::new(m).ok());
    let mut cache: BTreeMap<String, Result<VerifiedElf, String>> = BTreeMap::new();
    let mut rows = Vec::new();
    let mut mapped = 0;
    let mut resolved = 0;
    for event in events {
        let (pc, mode) = match event.payload {
            EventPayload::SoftwareSampleV2 { pc, mode, .. }
            | EventPayload::SoftwareStackV3 { pc, mode, .. } => (pc, mode),
            _ => continue,
        };
        let mut association = None;
        let outcome = (|| -> Result<crate::artifact::ElfAddress, String> {
            let m = metadata.ok_or("mapping metadata unavailable")?;
            let t = timeline.as_ref().ok_or("mapping metadata invalid")?;
            let (sha, offset, kernel) = if mode == 2 {
                let mapping = t
                    .lookup(event.task_id, event.pid, event.tid, event.timestamp_ns, pc)
                    .map_err(String::from)?;
                mapped += 1;
                let sha = mapping.sha256.clone();
                let offset = mapping.file_offset;
                association = Some(mapping);
                (sha.ok_or("mapped object SHA unavailable")?, offset, None)
            } else if mode == 1 {
                if event.timestamp_ns < t.journal.started_ns
                    || event.timestamp_ns >= t.journal.snapshot_ns
                    || t.journal.dropped != 0
                {
                    return Err("kernel mapping coverage unavailable".into());
                }
                let link = m.kernel.as_ref().ok_or("kernel artifact unavailable")?;
                let mut runtime = None;
                for row in &t.journal.entries {
                    if let MappingEvent::Kernel {
                        start,
                        len,
                        reference,
                        symbol,
                    } = &row.event
                    {
                        if row.timestamp_ns == event.timestamp_ns {
                            return Err("kernel mapping timestamp tie".into());
                        }
                        if row.timestamp_ns < event.timestamp_ns {
                            if runtime.is_some() {
                                return Err("multiple kernel mapping identities".into());
                            }
                            runtime = Some((*start, *len, *reference, symbol.as_str()));
                        }
                    }
                }
                let runtime = runtime.ok_or("runtime kernel text unavailable")?;
                (link.sha256.clone(), 0, Some((link, runtime)))
            } else {
                return Err("sample privilege unavailable".into());
            };
            let root = bundle.ok_or("artifact bundle not selected")?;
            let artifact = m
                .artifacts
                .iter()
                .find(|a| a.sha256 == sha)
                .ok_or("mapped ELF absent from captured bundle")?;
            let elf = cache
                .entry(sha)
                .or_insert_with(|| VerifiedElf::from_bundle(root, artifact, analyzer.target_arch()))
                .as_ref()
                .map_err(Clone::clone)?;
            if let Some((link, (start, len, reference, symbol))) = kernel {
                elf.kernel_address(link, start, len, reference, symbol, pc)
            } else {
                elf.address_for_file_offset(offset)
            }
        })();
        let identity = if let Some(m) = association {
            format!(
                "{{\"space\":{},\"exec\":{},\"class\":\"user\",\"comm\":{},\"start\":{},\"len\":\
                 {},\"byte_pgoff\":{},\"permissions\":{},\"object\":{},\"file_offset\":{},\"\
                 sha256\":{},\"path\":{}}}",
                m.space,
                m.exec,
                quote(&m.comm),
                m.mapping.start,
                m.mapping.len,
                m.mapping.pgoff,
                m.mapping.permissions,
                m.mapping.object,
                m.file_offset,
                m.sha256.as_deref().map(quote).unwrap_or("null".into()),
                quote(&m.path)
            )
        } else {
            "null".into()
        };
        let (symbol, error) = match outcome {
            Ok(a) => {
                resolved += 1;
                (
                    format!(
                        "{{\"sha256\":{},\"elf_address\":{},\"name\":{},\"offset\":{}}}",
                        quote(&a.sha256),
                        a.virtual_address,
                        a.symbol.as_deref().map(quote).unwrap_or("null".into()),
                        a.symbol_offset
                            .map(|o| o.to_string())
                            .unwrap_or("null".into())
                    ),
                    "null".into(),
                )
            }
            Err(error) => ("null".into(), quote(&error)),
        };
        rows.push(format!(
            "{{\"timestamp_ns\":{},\"cpu\":{},\"task\":{},\"pid\":{},\"tid\":{},\"ip\":{},\"mode\"\
             :{},\"mapping\":{},\"elf\":{},\"unknown_reason\":{}}}",
            event.timestamp_ns,
            event.cpu_id,
            event.task_id,
            event.pid,
            event.tid,
            pc,
            mode,
            identity,
            symbol,
            error
        ));
    }
    format!(
        "{{\"mapping_metadata\":{},\"journal_dropped\":{},\"busy_time_ns\":null,\"idle_time_ns\":\
         null,\"selected_samples\":{},\"mapped_user_samples\":{},\"verified_elf_samples\":{},\"\
         samples\":[{}]}}",
        metadata.is_some(),
        timeline
            .as_ref()
            .map(|t| t.journal.dropped.to_string())
            .unwrap_or("null".into()),
        rows.len(),
        mapped,
        resolved,
        rows.join(",")
    )
}
