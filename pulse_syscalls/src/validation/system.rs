use axerrno::LinuxError;
use linux_raw_sys::general::{
    GRND_INSECURE, GRND_NONBLOCK, GRND_RANDOM, LINUX_REBOOT_CMD_CAD_OFF, LINUX_REBOOT_CMD_CAD_ON,
    LINUX_REBOOT_CMD_HALT, LINUX_REBOOT_CMD_POWER_OFF, LINUX_REBOOT_CMD_RESTART,
    LINUX_REBOOT_CMD_RESTART2, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_MAGIC2A,
    LINUX_REBOOT_MAGIC2B, LINUX_REBOOT_MAGIC2C,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RebootAction {
    Restart,
    Restart2,
    Halt,
    PowerOff,
    SetCad(bool),
}

pub(crate) fn decode_reboot_action(
    magic1: usize,
    magic2: usize,
    cmd: usize,
) -> Result<RebootAction, LinuxError> {
    let valid_magic2 = matches!(
        magic2 as u32,
        LINUX_REBOOT_MAGIC2 | LINUX_REBOOT_MAGIC2A | LINUX_REBOOT_MAGIC2B | LINUX_REBOOT_MAGIC2C
    );
    if magic1 as u32 != LINUX_REBOOT_MAGIC1 || !valid_magic2 {
        return Err(LinuxError::EINVAL);
    }

    match cmd as u32 {
        LINUX_REBOOT_CMD_RESTART => Ok(RebootAction::Restart),
        LINUX_REBOOT_CMD_RESTART2 => Ok(RebootAction::Restart2),
        LINUX_REBOOT_CMD_HALT => Ok(RebootAction::Halt),
        LINUX_REBOOT_CMD_POWER_OFF => Ok(RebootAction::PowerOff),
        LINUX_REBOOT_CMD_CAD_ON => Ok(RebootAction::SetCad(true)),
        LINUX_REBOOT_CMD_CAD_OFF => Ok(RebootAction::SetCad(false)),
        _ => Err(LinuxError::EINVAL),
    }
}

pub(crate) fn reboot_action_requires_filesystem_flush(action: RebootAction) -> bool {
    matches!(
        action,
        RebootAction::Restart
            | RebootAction::Restart2
            | RebootAction::Halt
            | RebootAction::PowerOff
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MembarrierCommand {
    Query,
    Global,
    GlobalExpedited,
    RegisterGlobalExpedited,
    PrivateExpedited,
    RegisterPrivateExpedited,
    PrivateExpeditedSyncCore,
    RegisterPrivateExpeditedSyncCore,
}

pub(crate) fn parse_membarrier_command(
    command: i32,
    flags: i32,
) -> Result<MembarrierCommand, LinuxError> {
    if flags != 0 {
        return Err(LinuxError::EINVAL);
    }
    match command {
        0 => Ok(MembarrierCommand::Query),
        1 => Ok(MembarrierCommand::Global),
        2 => Ok(MembarrierCommand::GlobalExpedited),
        4 => Ok(MembarrierCommand::RegisterGlobalExpedited),
        8 => Ok(MembarrierCommand::PrivateExpedited),
        16 => Ok(MembarrierCommand::RegisterPrivateExpedited),
        32 => Ok(MembarrierCommand::PrivateExpeditedSyncCore),
        64 => Ok(MembarrierCommand::RegisterPrivateExpeditedSyncCore),
        _ => Err(LinuxError::EINVAL),
    }
}

pub(crate) fn validate_getrandom(
    buffer: usize,
    length: usize,
    flags: usize,
) -> Result<u32, LinuxError> {
    let flags = flags as u32;
    let allowed = GRND_RANDOM | GRND_NONBLOCK | GRND_INSECURE;
    if flags & !allowed != 0 || flags & (GRND_RANDOM | GRND_INSECURE) == GRND_RANDOM | GRND_INSECURE
    {
        return Err(LinuxError::EINVAL);
    }
    if length != 0 && buffer == 0 {
        return Err(LinuxError::EFAULT);
    }
    Ok(flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ltp_reboot01_accepts_cad_commands() {
        let magic1 = LINUX_REBOOT_MAGIC1 as usize;
        let magic2 = LINUX_REBOOT_MAGIC2 as usize;
        assert_eq!(
            decode_reboot_action(magic1, magic2, LINUX_REBOOT_CMD_CAD_ON as usize),
            Ok(RebootAction::SetCad(true))
        );
        assert_eq!(
            decode_reboot_action(magic1, magic2, LINUX_REBOOT_CMD_CAD_OFF as usize),
            Ok(RebootAction::SetCad(false))
        );
    }

    #[test]
    fn reboot_rejects_each_invalid_magic() {
        let magic1 = LINUX_REBOOT_MAGIC1 as usize;
        let magic2 = LINUX_REBOOT_MAGIC2 as usize;
        assert_eq!(
            decode_reboot_action(magic1 ^ 1, magic2, LINUX_REBOOT_CMD_RESTART as usize),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            decode_reboot_action(magic1, magic2 ^ 1, LINUX_REBOOT_CMD_RESTART as usize),
            Err(LinuxError::EINVAL)
        );
    }

    #[test]
    fn reboot_flushes_only_power_transitions() {
        for action in [
            RebootAction::Restart,
            RebootAction::Restart2,
            RebootAction::Halt,
            RebootAction::PowerOff,
        ] {
            assert!(reboot_action_requires_filesystem_flush(action));
        }
        assert!(!reboot_action_requires_filesystem_flush(
            RebootAction::SetCad(true)
        ));
        assert!(!reboot_action_requires_filesystem_flush(
            RebootAction::SetCad(false)
        ));
    }

    #[test]
    fn ltp_membarrier01_rejects_invalid_command_and_flags() {
        assert_eq!(parse_membarrier_command(-1, 0), Err(LinuxError::EINVAL));
        assert_eq!(parse_membarrier_command(0, 1), Err(LinuxError::EINVAL));
    }

    #[test]
    fn membarrier_maps_all_supported_commands() {
        let cases = [
            (0, MembarrierCommand::Query),
            (1, MembarrierCommand::Global),
            (2, MembarrierCommand::GlobalExpedited),
            (4, MembarrierCommand::RegisterGlobalExpedited),
            (8, MembarrierCommand::PrivateExpedited),
            (16, MembarrierCommand::RegisterPrivateExpedited),
            (32, MembarrierCommand::PrivateExpeditedSyncCore),
            (64, MembarrierCommand::RegisterPrivateExpeditedSyncCore),
        ];
        for (command, expected) in cases {
            assert_eq!(parse_membarrier_command(command, 0), Ok(expected));
        }
    }

    #[test]
    fn ltp_getrandom01_null_buffer_is_valid_only_for_zero_length() {
        assert_eq!(validate_getrandom(0, 0, 0), Ok(0));
        assert_eq!(
            validate_getrandom(0, 0, GRND_RANDOM as usize),
            Ok(GRND_RANDOM)
        );
        assert_eq!(validate_getrandom(0, 100, 0), Err(LinuxError::EFAULT));
    }

    #[test]
    fn ltp_getrandom05_rejects_invalid_flags() {
        assert_eq!(
            validate_getrandom(0x1000, 64, usize::MAX),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_getrandom(0x1000, 64, (GRND_RANDOM | GRND_INSECURE) as usize),
            Err(LinuxError::EINVAL)
        );
    }

    #[test]
    fn getrandom_accepts_each_supported_mode_and_combination() {
        for flags in [
            0,
            GRND_RANDOM,
            GRND_NONBLOCK,
            GRND_INSECURE,
            GRND_RANDOM | GRND_NONBLOCK,
            GRND_NONBLOCK | GRND_INSECURE,
        ] {
            assert_eq!(validate_getrandom(0x1000, 64, flags as usize), Ok(flags));
        }
    }
}
