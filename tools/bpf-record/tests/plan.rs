use bpf_record::{Capabilities, Event, Options, SessionPlan};

fn capabilities() -> Capabilities {
    Capabilities::from_stats(
        "PULSE_BPF_STATS version=1 pid=2 available=1 capabilities_version=1 online_mask=5 \
         cpu_clock=1 task_clock=1 sched=1 fault=1 min_period_ns=1 stack_context_version=3 \
         stack_depth=32 stack_bytes=512\nEND events=0 programs=0\n",
    )
    .unwrap()
}

#[test]
fn actual_cli_plan_expands_online_cpus_and_preserves_duplicate_sources() {
    let options = Options::parse(&[
        "--events",
        "cpu,cpu,sched,fault",
        "--cpus",
        "all",
        "--frequency",
        "99",
        "--duration-ms",
        "250",
        "--output",
        "/tmp/real.pbcap",
    ])
    .unwrap();
    let plan = SessionPlan::new(options, capabilities()).unwrap();
    assert_eq!(plan.cpus, [0, 2]);
    assert_eq!(plan.sources.len(), 18);
    assert_eq!(plan.period_ns, 10_101_011);
    assert_eq!(plan.duration_ns, Some(250_000_000));
    assert_eq!(plan.sources[0].event, Event::Cpu);
    assert_eq!(plan.sources[2].event, Event::Cpu);
    assert_ne!(plan.sources[0].id, plan.sources[2].id);
    assert!(plan.evidence().contains("requested_frequency=99"));
}

#[test]
fn invalid_cli_combinations_are_rejected_without_preparing_sources() {
    let base = ["--events", "cpu", "--output", "/tmp/session"];
    for extra in [
        vec!["--cpus", "1"],
        vec!["--cpus", "0,0"],
        vec!["--cpus", ""],
        vec!["--frequency", "0"],
        vec!["--frequency", "1000000001"],
        vec!["--frequency", "99", "--period-ns", "1000"],
        vec!["--period-ns", "0"],
        vec!["--duration-ms", "0"],
        vec!["--duration-ms", "18446744073709551615"],
        vec!["--buffer-pages", "3"],
        vec!["--buffer-pages", "512"],
        vec!["--record-bytes", "1"],
        vec!["--tid", "123"],
        vec!["--inherit", "1"],
        vec!["--exclude-kernel", "1"],
    ] {
        let mut args = base.to_vec();
        args.extend(extra);
        assert!(
            Options::parse(&args)
                .and_then(|o| SessionPlan::new(o, capabilities()))
                .is_err(),
            "{args:?}"
        );
    }
    for events in ["task", "bogus", "cpu,", "cycles"] {
        let options = Options::parse(&["--events", events, "--output", "/tmp/session"]).unwrap();
        assert!(
            SessionPlan::new(options, capabilities()).is_err(),
            "{events}"
        );
    }
    assert!(Options::parse(&[]).is_err());
}

#[test]
fn fallback_is_explicit_and_changes_recorded_units() {
    let options = Options::parse(&[
        "--events",
        "cycles",
        "--allow-fallback",
        "--output",
        "/tmp/session",
    ])
    .unwrap();
    let plan = SessionPlan::new(options, capabilities()).unwrap();
    assert!(plan.fallback.as_ref().unwrap().contains("nanoseconds"));
    assert!(plan.sources.iter().all(|s| s.event == Event::Cpu));
    assert!(plan.evidence().contains("requested_events=cycles"));
}

#[test]
fn mixed_fallback_preserves_each_sources_requested_mode() {
    use bpf_capture::recorder::SourceConfig;

    let options = Options::parse(&[
        "--events",
        "cpu,cycles,task,sched,fault",
        "--tid",
        "123",
        "--allow-fallback",
        "--output",
        "/tmp/session",
    ])
    .unwrap();
    let plan = SessionPlan::new(options, capabilities()).unwrap();
    assert_eq!(plan.sources[0].requested_config, SourceConfig::CpuClock);
    assert_eq!(
        plan.sources[2].requested_config,
        SourceConfig::HardwareCycles
    );
    assert_eq!(plan.sources[2].event, Event::Cpu);
    assert_eq!(plan.sources[4].requested_config, SourceConfig::TaskClock);
    assert!(
        plan.sources[5..]
            .iter()
            .all(|s| s.requested_config == SourceConfig::Tracepoint)
    );
}

#[test]
fn task_scope_cannot_silently_restrict_migration_or_substitute_a_workload() {
    let args = [
        "--events",
        "cpu,task",
        "--tid",
        "123",
        "--output",
        "/tmp/session",
    ];
    let plan = SessionPlan::new(Options::parse(&args).unwrap(), capabilities()).unwrap();
    assert_eq!(plan.sink_cpus, [0, 2]);
    assert_eq!(plan.sources.last().unwrap().tid, Some(123));
    assert_eq!(plan.sources.last().unwrap().cpu, None);
    let mut restricted = args.to_vec();
    restricted.extend(["--cpus", "0"]);
    assert!(SessionPlan::new(Options::parse(&restricted).unwrap(), capabilities()).is_err());
}

#[test]
fn plan_constructor_revalidates_public_options_and_capabilities() {
    let mut options = Options::parse(&["--events", "cpu", "--output", "/tmp/session"]).unwrap();
    options.events.clear();
    assert!(SessionPlan::new(options, capabilities()).is_err());
}

#[test]
fn real_stack_request_preserves_mixed_and_duplicate_source_plans() {
    let options = Options::parse(&[
        "--events",
        "cpu,cpu,task,sched,fault",
        "--tid",
        "123",
        "--callchain",
        "fp",
        "--stack-depth",
        "32",
        "--stack-bytes",
        "512",
        "--output",
        "/tmp/stacks.pbcap",
    ])
    .unwrap();
    let plan = SessionPlan::new(options, capabilities()).unwrap();
    assert_eq!(plan.sources.len(), 19);
    assert!(
        plan.evidence()
            .contains("requested_callchain=fp effective_callchain=fp")
    );
    assert!(
        plan.evidence()
            .contains("effective_stack_depth=32 effective_stack_bytes=512")
    );
    assert!(plan.sources[..5].iter().all(|source| {
        source.kind == bpf_capture::RecorderKind::SoftwareStackV3
            && source.context_size() == 640
            && source.schema_version() == 3
            && source.event_id() == 0x1002
    }));
    assert!(plan.sources[5..].iter().all(|source| {
        source.kind == bpf_capture::RecorderKind::Tracepoint
            && source.schema_version() == 1
            && source.event_id() == source.event.config() as u32
    }));
    assert_eq!(plan.sources[0].id, 1);
    assert_eq!(plan.sources[2].id, 3);
}

#[test]
fn malformed_stack_capability_cannot_trigger_a_fallback() {
    let options = Options::parse(&[
        "--events",
        "cpu",
        "--allow-fallback",
        "--output",
        "/tmp/session",
    ])
    .unwrap();
    let mut caps = capabilities();
    caps.stack_depth = 0;
    assert!(SessionPlan::new(options, caps).is_err());
}

#[test]
fn default_stack_plan_accounts_for_per_cpu_map_slots_with_cpu_holes() {
    let plan = SessionPlan::new(
        Options::parse(&["--events", "cpu", "--output", "/tmp/session"]).unwrap(),
        capabilities(),
    )
    .unwrap();
    assert!(
        plan.sources
            .iter()
            .all(|source| source.kind == bpf_capture::RecorderKind::SoftwareStackV3)
    );
    assert!(plan.evidence().contains("scratch_map_bytes=3984"));
}

#[test]
fn capture_output_cannot_replace_requested_kernel_artifact() {
    let options = Options::parse(&[
        "--events",
        "cpu",
        "--kernel-elf",
        "/tmp/kernel",
        "--output",
        "/tmp/kernel",
    ])
    .unwrap();
    assert!(SessionPlan::new(options, capabilities()).is_err());
}

#[test]
fn unavailable_stack_capability_requires_explicit_fallback_and_preserves_request() {
    let mut caps = capabilities();
    caps.stack_context_version = 0;
    caps.stack_depth = 0;
    caps.stack_bytes = 0;
    let mut args = vec!["--events", "cpu", "--output", "/tmp/session"];
    assert!(SessionPlan::new(Options::parse(&args).unwrap(), caps.clone()).is_err());
    args.push("--allow-fallback");
    let plan = SessionPlan::new(Options::parse(&args).unwrap(), caps.clone()).unwrap();
    assert!(
        plan.evidence()
            .contains("requested_callchain=fp effective_callchain=none")
    );
    assert!(
        plan.fallback
            .as_ref()
            .unwrap()
            .contains("frame-pointer unavailable")
    );
    assert_eq!(plan.stack_depth, 0);
    assert_eq!(plan.stack_bytes, 0);
    assert!(
        plan.sources
            .iter()
            .all(|source| source.kind == bpf_capture::RecorderKind::SoftwareV2)
    );

    let options = Options::parse(&[
        "--events",
        "cycles",
        "--allow-fallback",
        "--output",
        "/tmp/session",
    ])
    .unwrap();
    let plan = SessionPlan::new(options, caps).unwrap();
    let reason = plan.fallback.unwrap();
    assert!(reason.contains("hardware-cycles unavailable"));
    assert!(reason.contains("frame-pointer unavailable"));
}

#[test]
fn unsupported_stack_requests_are_not_silently_adjusted_even_with_fallback() {
    for extra in [
        vec!["--callchain", "dwarf"],
        vec!["--stack-depth", "0"],
        vec!["--stack-depth", "1"],
        vec!["--stack-depth", "33"],
        vec!["--stack-depth", "18446744073709551615"],
        vec!["--stack-bytes", "0"],
        vec!["--stack-bytes", "256"],
        vec!["--callchain", "none", "--stack-depth", "32"],
        vec!["--callchain", "none", "--stack-bytes", "512"],
        vec!["--callchain", "fp", "--callchain", "none"],
        vec!["--kernel-elf", ""],
        vec!["--kernel-elf", "/kernel\0alias"],
    ] {
        let mut args = vec![
            "--events",
            "cpu",
            "--allow-fallback",
            "--output",
            "/tmp/session",
        ];
        args.extend(extra);
        assert!(
            Options::parse(&args)
                .and_then(|options| SessionPlan::new(options, capabilities()))
                .is_err(),
            "{args:?}"
        );
    }
}

#[test]
fn trace_only_and_explicit_no_chain_sessions_preserve_their_contexts() {
    let args = ["--events", "sched,fault", "--output", "/tmp/session"];
    let plan = SessionPlan::new(Options::parse(&args).unwrap(), capabilities()).unwrap();
    assert_eq!(plan.effective_callchain, bpf_record::Callchain::None);
    assert!(
        plan.sources
            .iter()
            .all(|source| source.kind == bpf_capture::RecorderKind::Tracepoint)
    );
    let mut explicit = args.to_vec();
    explicit.extend(["--callchain", "fp", "--allow-fallback"]);
    assert!(SessionPlan::new(Options::parse(&explicit).unwrap(), capabilities()).is_err());

    let plan = SessionPlan::new(
        Options::parse(&[
            "--events",
            "cpu",
            "--callchain",
            "none",
            "--output",
            "/tmp/session",
        ])
        .unwrap(),
        capabilities(),
    )
    .unwrap();
    assert!(plan.sources.iter().all(|source| source.context_size() == 64
        && source.schema_version() == 2
        && source.event_id() == 0x1001));
    assert!(plan.fallback.is_none());
}

#[test]
fn capability_snapshot_must_declare_current_stack_geometry() {
    let header = "PULSE_BPF_STATS version=1 available=1 capabilities_version=1 online_mask=5 \
                  cpu_clock=1 task_clock=1 sched=1 fault=1 min_period_ns=1";
    for geometry in [
        "",
        "stack_context_version=3 stack_depth=0 stack_bytes=512",
        "stack_context_version=3 stack_depth=32 stack_bytes=513",
        "stack_context_version=0 stack_depth=32 stack_bytes=512",
        "stack_context_version=4 stack_depth=32 stack_bytes=512",
        "stack_context_version=3 stack_depth=32 stack_bytes=512 stack_depth=32",
    ] {
        assert!(
            Capabilities::from_stats(&format!("{header} {geometry}\nEND events=0 programs=0\n"))
                .is_err()
        );
    }
    assert!(
        Capabilities::from_stats(&format!(
            "{header} stack_context_version=0 stack_depth=0 stack_bytes=0\nEND events=0 \
             programs=0\n"
        ))
        .is_ok()
    );
}

#[test]
fn stack_source_budget_is_bounded_before_resources_are_prepared() {
    let mut options = Options::parse(&["--events", "cpu", "--output", "/tmp/session"]).unwrap();
    options.events = vec!["cpu".into(); 65];
    assert!(SessionPlan::new(options, capabilities()).is_err());
}
