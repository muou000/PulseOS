use std::{
    env, fs,
    io::{Read, Write},
    process::exit,
};

use bpf_analyzer::{
    CaptureAnalyzer, emission,
    query::{Privilege, Query, SampleWeight},
};

fn print_help() {
    println!("Usage: bpf-analyzer <capture-file> [OPTIONS]");
    println!("  --table, -t          Print selected normalized events");
    println!("  --loss, -l           Print capture-wide loss/integrity diagnostics");
    println!("  --json, -j           Print JSON for the selected report");
    println!("  --fault-report      Report fault outcomes and resolver wall-time");
    println!("  --sched-report      Report blocked and wake-to-switch intervals");
    println!("  --mode user|kernel   Filter explicit sample mode or fault origin");
    println!("  --phase <NAME>      Select one unique closed phase window");
    println!("  --from-ns <N> --to-ns <N>  Intersect a half-open time window");
    println!("  --task <ID> --pid <PID> --tid <TID> --cpu <CPU>  Intersect subject filters");
    println!("  --address-start <N> --address-end <N>  Fault address range (decimal/hex)");
    println!("  --timeline <FILE>    Write observed events and qualified intervals as JSON");
    println!("  --weight samples|period   CPU folded weight (default samples)");
    println!("  --oncpu <FILE>      Write CPU sample folded data; empty when no samples");
    println!("  --offcpu <FILE>     Write observed blocked intervals in nanoseconds");
    println!("  --help, -h          Show help");
}
fn value<'a>(args: &'a [String], index: &mut usize, name: &str) -> Result<&'a str, String> {
    *index += 1;
    args.get(*index)
        .map(String::as_str)
        .ok_or_else(|| format!("{name} requires a value"))
}
fn unsigned(value: &str, name: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|v| v.is_ascii_digit()) {
        return Err(format!("{name} requires an unsigned decimal integer"));
    }
    value.parse().map_err(|_| format!("{name} is out of range"))
}
fn address(value: &str, name: &str) -> Result<u64, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|_| format!("{name} requires a valid u64 address"))
    } else {
        unsigned(value, name)
    }
}
fn opened_identity(file: &fs::File) -> Result<(u64, u64), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file
            .metadata()
            .map_err(|error| format!("cannot inspect open file: {error}"))?;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err(
            "safe report-file output requires Unix file identity; stdout reports remain available"
                .into(),
        )
    }
}
struct ReportFiles {
    files: [Option<fs::File>; 3],
}
impl ReportFiles {
    fn prepare(input: &fs::File, paths: [Option<&str>; 3]) -> Result<Self, String> {
        let mut result = Self {
            files: std::array::from_fn(|_| None),
        };
        if paths.iter().all(Option::is_none) {
            return Ok(result);
        }
        let source = opened_identity(input)?;
        let mut identities = std::collections::BTreeSet::new();
        for (index, path) in paths.into_iter().enumerate() {
            let Some(path) = path else {
                continue;
            };
            // Open once without truncation. Subsequent inspection and writing
            // use this same handle, so path replacement cannot switch the file
            // being written after validation.
            let file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
                .map_err(|error| format!("cannot open report {path}: {error}"))?;
            if !file.metadata().map_err(|e| e.to_string())?.is_file() {
                return Err(format!("report output must be a regular file: {path}"));
            }
            let identity = opened_identity(&file)?;
            if identity == source {
                return Err(format!("report output aliases its source capture: {path}"));
            }
            if !identities.insert(identity) {
                return Err(format!("report outputs refer to the same file: {path}"));
            }
            result.files[index] = Some(file);
        }
        // No existing report is truncated until every destination is checked.
        Ok(result)
    }
    fn write(&mut self, index: usize, bytes: &[u8]) -> Result<(), String> {
        let file = self.files[index]
            .as_mut()
            .ok_or("report was not prepared")?;
        file.set_len(0)
            .and_then(|_| file.write_all(bytes))
            .map_err(|e| format!("failed to write report: {e}"))
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let mut query = Query::default();
    let (mut table, mut loss, mut json, mut scheduler, mut faults) =
        (false, false, false, false, false);
    let (mut oncpu, mut offcpu, mut timeline) = (None, None, None);
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--table" | "-t" => table = true,
            "--loss" | "-l" => loss = true,
            "--json" | "-j" => json = true,
            "--sched-report" => scheduler = true,
            "--fault-report" => faults = true,
            "--mode" => {
                query.mode = Some(match value(args, &mut i, "--mode")? {
                    "user" => Privilege::User,
                    "kernel" => Privilege::Kernel,
                    _ => {
                        return Err(
                            "--mode must be user or kernel; absent mode is never inferred".into(),
                        );
                    }
                })
            }
            "--phase" => query.phase = Some(value(args, &mut i, "--phase")?.into()),
            "--from-ns" => {
                query.from_ns = Some(unsigned(value(args, &mut i, "--from-ns")?, "--from-ns")?)
            }
            "--to-ns" => query.to_ns = Some(unsigned(value(args, &mut i, "--to-ns")?, "--to-ns")?),
            "--task" => query.task_id = Some(unsigned(value(args, &mut i, "--task")?, "--task")?),
            "--pid" | "--tid" | "--cpu" => {
                let name = args[i].clone();
                let parsed = u32::try_from(unsigned(value(args, &mut i, &name)?, &name)?)
                    .map_err(|_| format!("{name} exceeds u32"))?;
                match name.as_str() {
                    "--pid" => query.pid = Some(parsed),
                    "--tid" => query.tid = Some(parsed),
                    _ => query.cpu = Some(parsed),
                }
            }
            "--address-start" => {
                query.address_start = Some(address(
                    value(args, &mut i, "--address-start")?,
                    "--address-start",
                )?)
            }
            "--address-end" => {
                query.address_end = Some(address(
                    value(args, &mut i, "--address-end")?,
                    "--address-end",
                )?)
            }
            "--weight" => {
                query.weight = match value(args, &mut i, "--weight")? {
                    "samples" => SampleWeight::Samples,
                    "period" => SampleWeight::Period,
                    _ => return Err("--weight must be samples or period".into()),
                }
            }
            "--timeline" => timeline = Some(value(args, &mut i, "--timeline")?.to_owned()),
            "--oncpu" => oncpu = Some(value(args, &mut i, "--oncpu")?.to_owned()),
            "--offcpu" => offcpu = Some(value(args, &mut i, "--offcpu")?.to_owned()),
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => return Err(format!("unknown option: {other}")),
        }
        i += 1;
    }
    if scheduler && query.mode.is_some() {
        return Err(
            "--sched-report cannot use --mode: scheduling events do not carry privilege".into(),
        );
    }
    if scheduler && faults {
        return Err("select one of --sched-report and --fault-report per report".into());
    }
    let mut input = fs::File::open(&args[1]).map_err(|e| format!("cannot open capture: {e}"))?;
    let mut capture_bytes = Vec::new();
    input
        .read_to_end(&mut capture_bytes)
        .map_err(|e| format!("cannot read capture: {e}"))?;
    let analyzer = CaptureAnalyzer::from_bytes(&capture_bytes)
        .map_err(|e| format!("failed to parse BPF capture: {e}"))?;
    let selected = analyzer.query(&query)?;
    let mut reports = ReportFiles::prepare(
        &input,
        [oncpu.as_deref(), offcpu.as_deref(), timeline.as_deref()],
    )?;
    if !table
        && !loss
        && !json
        && !scheduler
        && !faults
        && oncpu.is_none()
        && offcpu.is_none()
        && timeline.is_none()
    {
        table = true;
        loss = true;
    }
    if loss {
        println!("{}", analyzer.render_loss_report());
    }
    if table {
        println!(
            "{}",
            emission::render_event_table(&analyzer, &selected.events)
        );
    }
    if scheduler {
        if json {
            println!(
                "{{\"query\":{},\"selected_records_count\":{},\"context_records_count\":{},\"query_clipped_intervals\":{},\"diagnostics_scope\":\"capture\",\"scheduler\":{}}}",
                emission::render_query_metadata(&selected),
                selected.events.len(),
                selected.context_records_count,
                selected.clipped_intervals,
                selected.scheduler.render_json()
            );
        } else {
            println!("{}", selected.scheduler.render_text());
        }
    } else if faults {
        let report = bpf_analyzer::fault::FaultReport::compute_in_window(
            &selected.events,
            analyzer.is_complete(),
            selected.from_ns,
            selected.to_ns,
        );
        if json {
            println!(
                concat!(
                    "{{\"query\":{},\"selected_records_count\":{},",
                    "\"context_records_count\":{},\"faults\":{}}}"
                ),
                emission::render_query_metadata(&selected),
                selected.events.len(),
                selected.context_records_count,
                report.render_json()
            );
        } else {
            println!("{}", report.render_text());
        }
    } else if json {
        println!("{}", emission::render_query_json(&analyzer, &selected));
    }
    if let Some(path) = oncpu {
        let folded =
            emission::render_on_cpu_folded_weighted(&analyzer, &selected.events, query.weight);
        reports.write(0, folded.text.as_bytes())?;
        eprintln!(
            "Wrote CPU folded {} (unit={}, selected samples only)",
            path,
            query.weight.unit()
        );
    }
    if let Some(path) = offcpu {
        let folded = emission::render_off_cpu_folded(&analyzer, &selected.stats);
        reports.write(1, folded.text.as_bytes())?;
        eprintln!(
            "Wrote blocked folded {} (unit=duration_ns, closed intervals only)",
            path
        );
    }
    if let Some(path) = timeline {
        let output = emission::render_timeline(&analyzer, &selected);
        reports.write(2, output.as_bytes())?;
        eprintln!(
            "Wrote timeline {} (observed records; no synthetic endpoints)",
            path
        );
    }
    Ok(())
}
fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        return;
    }
    if let Err(error) = run(&args) {
        eprintln!("Error: {error}");
        exit(1);
    }
}
