fn main() {
    println!("cargo:rerun-if-env-changed=AX_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PULSE_BUILD_EPOCH");
    if let Ok(config_path) = std::env::var("AX_CONFIG_PATH") {
        println!("cargo:rerun-if-changed={config_path}");
    }

    let build_epoch = std::env::var("PULSE_BUILD_EPOCH")
        .map(|value| {
            value
                .parse::<u64>()
                .expect("PULSE_BUILD_EPOCH must be Unix seconds")
        })
        .unwrap_or_else(|_| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock must be after the Unix epoch")
                .as_secs()
        });
    assert!(
        build_epoch >= 978_307_200,
        "PULSE_BUILD_EPOCH must be no earlier than 2001-01-01"
    );
    println!("cargo:rustc-env=PULSE_BUILD_EPOCH={build_epoch}");
}
