//! Test-build-only observation of the calling task's file I/O transaction.
//!
//! This module is absent from normal kernels. The probe resets immediately
//! before one syscall and snapshots before doing any diagnostic or verification
//! I/O, so unrelated tasks and the writeback daemon do not affect its counts.

use axerrno::LinuxError;

pub(super) const PR_FILE_IO_TEST: u32 = 0x5053_4749;

pub(super) fn prctl(command: usize, address: usize, size: usize, reserved: usize) -> isize {
    if command == 3 && reserved == 0 {
        return super::file_io_layout::query_layout(address, size)
            .map_or_else(|error| -(error.code() as isize), |count| count as isize);
    }
    let result = (|| -> Result<(), LinuxError> {
        if reserved != 0 {
            return Err(LinuxError::EINVAL);
        }
        match command {
            0 if address == 0 && size == 0 => {
                axfs::file_io_test_begin(axtask::current().id().as_u64());
                Ok(())
            }
            1 if size == 5 * size_of::<u64>() => {
                if !axfs::file_io_test_pins_balanced() {
                    return Err(LinuxError::EIO);
                }
                let snapshot = axfs::file_io_test_snapshot();
                let values = [
                    1u64,
                    snapshot.position_acquisitions,
                    snapshot.operations,
                    snapshot.pin_peak_pages,
                    snapshot.staged_bytes,
                ];
                let mut bytes = [0u8; 5 * size_of::<u64>()];
                for (value, target) in values.iter().zip(bytes.chunks_exact_mut(8)) {
                    target.copy_from_slice(&value.to_le_bytes());
                }
                super::utils::write_user_bytes(address, &bytes)
            }
            2 if address == 0 && size == 0 => {
                if !axfs::file_io_test_pins_balanced() {
                    return Err(LinuxError::EIO);
                }
                axfs::file_io_test_disable();
                Ok(())
            }
            4 if address == 0 && size == 0 => {
                axfs::run_file_io_checks().map_err(Into::into)
            }
            _ => Err(LinuxError::EINVAL),
        }
    })();
    result.map_or_else(|error| -(error.code() as isize), |()| 0)
}
