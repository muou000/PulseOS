use bpf_analyzer::CaptureAnalyzer;
use std::env;
use std::fs;
use std::path::Path;
use std::process::exit;

fn print_help() {
    println!("Usage: bpf-analyzer <capture-file> [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --table, -t          Print normalized event table");
    println!("  --loss, -l           Print loss and integrity summary report");
    println!("  --json, -j           Print machine-readable JSON output");
    println!("  --phase <NAME>       Filter events and statistics by phase marker window");
    println!("  --oncpu <FILE>       Emit FlameGraph folded on-CPU stacks to FILE");
    println!("  --offcpu <FILE>      Emit FlameGraph folded off-CPU stacks to FILE");
    println!("  --help, -h           Show this help message");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        return;
    }

    let capture_path = &args[1];
    if !Path::new(capture_path).exists() {
        eprintln!("Error: capture file '{}' not found", capture_path);
        exit(1);
    }

    let analyzer = match CaptureAnalyzer::from_file(capture_path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Failed to parse BPF capture: {}", e);
            exit(1);
        }
    };

    let mut show_table = false;
    let mut show_loss = false;
    let mut show_json = false;
    let mut phase_filter: Option<String> = None;
    let mut oncpu_out: Option<String> = None;
    let mut offcpu_out: Option<String> = None;

    let mut idx = 2;
    while idx < args.len() {
        match args[idx].as_str() {
            "--table" | "-t" => show_table = true,
            "--loss" | "-l" => show_loss = true,
            "--json" | "-j" => show_json = true,
            "--phase" => {
                idx += 1;
                if idx < args.len() {
                    phase_filter = Some(args[idx].clone());
                } else {
                    eprintln!("Error: --phase requires a name");
                    exit(1);
                }
            }
            "--oncpu" => {
                idx += 1;
                if idx < args.len() {
                    oncpu_out = Some(args[idx].clone());
                } else {
                    eprintln!("Error: --oncpu requires an output file path");
                    exit(1);
                }
            }
            "--offcpu" => {
                idx += 1;
                if idx < args.len() {
                    offcpu_out = Some(args[idx].clone());
                } else {
                    eprintln!("Error: --offcpu requires an output file path");
                    exit(1);
                }
            }
            other => {
                eprintln!("Unknown option: {}", other);
                print_help();
                exit(1);
            }
        }
        idx += 1;
    }

    // Default: print loss report and event table if no specific output flags given
    if !show_table && !show_loss && !show_json && oncpu_out.is_none() && offcpu_out.is_none() {
        show_loss = true;
        show_table = true;
    }

    if show_loss {
        println!("{}", analyzer.render_loss_report());
    }

    if show_table {
        let events = if let Some(ref ph) = phase_filter {
            analyzer.events_in_phase(ph)
        } else {
            analyzer.ordered_events()
        };
        println!("{}", bpf_analyzer::emission::render_event_table(&analyzer, &events));
    }

    if show_json {
        println!("{}", analyzer.render_json());
    }

    if let Some(path) = oncpu_out {
        let folded = analyzer.render_on_cpu_folded();
        if let Err(e) = fs::write(&path, &folded.text) {
            eprintln!("Failed to write on-CPU folded output to '{}': {}", path, e);
            exit(1);
        }
        println!("Wrote on-CPU folded profile to {}", path);
    }

    if let Some(path) = offcpu_out {
        let folded = analyzer.render_off_cpu_folded();
        if let Err(e) = fs::write(&path, &folded.text) {
            eprintln!("Failed to write off-CPU folded output to '{}': {}", path, e);
            exit(1);
        }
        println!("Wrote off-CPU folded profile to {}", path);
    }
}
