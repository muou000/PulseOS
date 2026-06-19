use axtask;
use core::time::Duration;

pub fn init_writeback_daemon() {
    axtask::spawn(move || {
        loop {
            axtask::sleep(Duration::from_secs(5));
            let _ = crate::flush_all_filesystems();
            let _ = crate::flush_all_disks();
        }
    });
}
