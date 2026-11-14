#[path = "../../pulse_core/src/task/sampling_clock.rs"]
mod sampling_clock;
use sampling_clock::OnCpuClock;

#[test]
fn selected_thread_clock_excludes_sleep_and_survives_migration() {
    let mut clock = OnCpuClock::new();
    assert_eq!(clock.read(50), 0);
    clock.enter(100);
    assert_eq!(clock.read(150), 50);
    clock.leave(180);
    assert_eq!(clock.read(900), 80);
    clock.enter(1000);
    assert_eq!(clock.read(1050), 130);
    clock.leave(1080);
    assert_eq!(clock.read(10_000), 160);
}

#[test]
fn repeated_switch_notifications_do_not_reset_or_double_count() {
    let mut clock = OnCpuClock::new();
    clock.enter(100);
    clock.enter(120);
    clock.leave(180);
    clock.leave(200);
    assert_eq!(clock.read(300), 80);
}
