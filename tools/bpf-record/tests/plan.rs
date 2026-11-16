use bpf_record::{Capabilities, Event, Options, SessionPlan};

fn capabilities() -> Capabilities {
    Capabilities::from_stats(
        "PULSE_BPF_STATS version=1 pid=2 available=1 capabilities_version=1 online_mask=5 \
         cpu_clock=1 task_clock=1 sched=1 fault=1 min_period_ns=1\nEND events=0 programs=0\n",
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
