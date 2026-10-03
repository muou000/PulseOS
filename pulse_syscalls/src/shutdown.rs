pub(crate) fn after_shutdown_checkpoint<T, E>(
    checkpoint: impl FnOnce() -> Result<(), E>,
    transition: impl FnOnce() -> T,
) -> Result<T, E> {
    checkpoint()?;
    Ok(transition())
}

#[cfg(all(feature = "mapping-lifecycle-test", target_os = "none"))]
pub fn run_mapping_shutdown_checks() -> axerrno::AxResult<()> {
    let mut reset_reached = false;
    let result =
        after_shutdown_checkpoint(axfs::mapping_lifecycle_failed_sync, || reset_reached = true);
    if result.is_ok() || reset_reached {
        return Err(axerrno::AxError::BadState);
    }
    let result =
        after_shutdown_checkpoint(|| axfs::flush_all_filesystems(), || reset_reached = true);
    if result.is_err() || !reset_reached {
        return Err(axerrno::AxError::BadState);
    }
    axlog::info!("MLC_KERNEL PASS sync_failure_refuses_reset");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::after_shutdown_checkpoint;

    #[test]
    fn failed_checkpoint_never_calls_transition() {
        let mut reached = false;
        assert_eq!(
            after_shutdown_checkpoint(|| Err::<(), _>(67), || reached = true),
            Err(67)
        );
        assert!(!reached);
        assert_eq!(
            after_shutdown_checkpoint(|| Ok::<(), u8>(()), || reached = true),
            Ok(())
        );
        assert!(reached);
    }
}
