use axerrno::LinuxError;

pub const BPF_OBJ_NAME_LEN: usize = 16;
pub const BPF_MAX_ATTR_SIZE: usize = 4096;

pub const BPF_ANY: u64 = 0;
pub const BPF_NOEXIST: u64 = 1;
pub const BPF_EXIST: u64 = 2;

pub const BPF_PERF_EVENT: u32 = 41;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BpfCmd {
    MapCreate = 0,
    MapLookupElem = 1,
    MapUpdateElem = 2,
    MapDeleteElem = 3,
    MapGetNextKey = 4,
    ProgLoad = 5,
    ObjPin = 6,
    ObjGet = 7,
    ProgAttach = 8,
    ProgDetach = 9,
    ProgTestRun = 10,
    ProgGetNextId = 11,
    MapGetNextId = 12,
    ProgGetFdById = 13,
    MapGetFdById = 14,
    ObjGetInfoByFd = 15,
    ProgQuery = 16,
    RawTracepointOpen = 17,
    BtfLoad = 18,
    BtfGetFdById = 19,
    TaskFdQuery = 20,
    MapLookupAndDeleteElem = 21,
    MapFreeze = 22,
    BtfGetNextId = 23,
    MapLookupBatch = 24,
    MapLookupAndDeleteBatch = 25,
    MapUpdateBatch = 26,
    MapDeleteBatch = 27,
    LinkCreate = 28,
    LinkUpdate = 29,
    LinkGetFdById = 30,
    LinkGetNextId = 31,
    EnableStats = 32,
    IterCreate = 33,
    LinkDetach = 34,
    ProgBindMap = 35,
}

impl BpfCmd {
    pub const ALL: [BpfCmd; 36] = [
        BpfCmd::MapCreate,
        BpfCmd::MapLookupElem,
        BpfCmd::MapUpdateElem,
        BpfCmd::MapDeleteElem,
        BpfCmd::MapGetNextKey,
        BpfCmd::ProgLoad,
        BpfCmd::ObjPin,
        BpfCmd::ObjGet,
        BpfCmd::ProgAttach,
        BpfCmd::ProgDetach,
        BpfCmd::ProgTestRun,
        BpfCmd::ProgGetNextId,
        BpfCmd::MapGetNextId,
        BpfCmd::ProgGetFdById,
        BpfCmd::MapGetFdById,
        BpfCmd::ObjGetInfoByFd,
        BpfCmd::ProgQuery,
        BpfCmd::RawTracepointOpen,
        BpfCmd::BtfLoad,
        BpfCmd::BtfGetFdById,
        BpfCmd::TaskFdQuery,
        BpfCmd::MapLookupAndDeleteElem,
        BpfCmd::MapFreeze,
        BpfCmd::BtfGetNextId,
        BpfCmd::MapLookupBatch,
        BpfCmd::MapLookupAndDeleteBatch,
        BpfCmd::MapUpdateBatch,
        BpfCmd::MapDeleteBatch,
        BpfCmd::LinkCreate,
        BpfCmd::LinkUpdate,
        BpfCmd::LinkGetFdById,
        BpfCmd::LinkGetNextId,
        BpfCmd::EnableStats,
        BpfCmd::IterCreate,
        BpfCmd::LinkDetach,
        BpfCmd::ProgBindMap,
    ];

    pub fn from_raw(raw: u32) -> Result<Self, LinuxError> {
        match raw {
            0 => Ok(Self::MapCreate),
            1 => Ok(Self::MapLookupElem),
            2 => Ok(Self::MapUpdateElem),
            3 => Ok(Self::MapDeleteElem),
            4 => Ok(Self::MapGetNextKey),
            5 => Ok(Self::ProgLoad),
            6 => Ok(Self::ObjPin),
            7 => Ok(Self::ObjGet),
            8 => Ok(Self::ProgAttach),
            9 => Ok(Self::ProgDetach),
            10 => Ok(Self::ProgTestRun),
            11 => Ok(Self::ProgGetNextId),
            12 => Ok(Self::MapGetNextId),
            13 => Ok(Self::ProgGetFdById),
            14 => Ok(Self::MapGetFdById),
            15 => Ok(Self::ObjGetInfoByFd),
            16 => Ok(Self::ProgQuery),
            17 => Ok(Self::RawTracepointOpen),
            18 => Ok(Self::BtfLoad),
            19 => Ok(Self::BtfGetFdById),
            20 => Ok(Self::TaskFdQuery),
            21 => Ok(Self::MapLookupAndDeleteElem),
            22 => Ok(Self::MapFreeze),
            23 => Ok(Self::BtfGetNextId),
            24 => Ok(Self::MapLookupBatch),
            25 => Ok(Self::MapLookupAndDeleteBatch),
            26 => Ok(Self::MapUpdateBatch),
            27 => Ok(Self::MapDeleteBatch),
            28 => Ok(Self::LinkCreate),
            29 => Ok(Self::LinkUpdate),
            30 => Ok(Self::LinkGetFdById),
            31 => Ok(Self::LinkGetNextId),
            32 => Ok(Self::EnableStats),
            33 => Ok(Self::IterCreate),
            34 => Ok(Self::LinkDetach),
            35 => Ok(Self::ProgBindMap),
            _ => Err(LinuxError::EINVAL),
        }
    }

    pub fn min_attr_size(self) -> usize {
        match self {
            Self::MapCreate => 20,
            Self::MapLookupElem | Self::MapGetNextKey => 24,
            Self::MapUpdateElem => 32,
            Self::MapDeleteElem => 16,
            Self::ProgLoad => 48,
            Self::ObjPin | Self::ObjGet => 16,
            Self::ProgAttach | Self::ProgDetach => 16,
            Self::ProgTestRun => 32,
            Self::ProgGetNextId
            | Self::MapGetNextId
            | Self::BtfGetNextId
            | Self::LinkGetNextId => 12,
            Self::ProgGetFdById
            | Self::MapGetFdById
            | Self::BtfGetFdById
            | Self::LinkGetFdById => 8,
            Self::ObjGetInfoByFd => 16,
            Self::ProgQuery => 24,
            Self::RawTracepointOpen => 12,
            Self::BtfLoad => 20,
            Self::TaskFdQuery => 24,
            Self::MapLookupAndDeleteElem | Self::MapFreeze => 16,
            Self::MapLookupBatch
            | Self::MapLookupAndDeleteBatch
            | Self::MapUpdateBatch
            | Self::MapDeleteBatch => 40,
            Self::LinkCreate | Self::LinkUpdate => 16,
            Self::EnableStats => 4,
            Self::IterCreate => 8,
            Self::LinkDetach => 4,
            Self::ProgBindMap => 12,
        }
    }

    pub fn is_deferred(self) -> bool {
        !matches!(
            self,
            Self::MapCreate
                | Self::MapLookupElem
                | Self::MapUpdateElem
                | Self::MapDeleteElem
                | Self::MapGetNextKey
                | Self::ObjGetInfoByFd
                | Self::ProgLoad
                | Self::LinkCreate
                | Self::LinkDetach
        )
    }

    /// Bytes of `union bpf_attr` consumed by an implemented command, i.e. the
    /// end of its last field. Linux `CHECK_ATTR` requires the rest to be zero.
    pub fn attr_used_size(self) -> usize {
        match self {
            Self::MapCreate => core::mem::size_of::<BpfMapCreateAttr>(),
            Self::MapLookupElem | Self::MapUpdateElem => core::mem::size_of::<BpfMapElemAttr>(),
            Self::MapDeleteElem => 16,
            Self::MapGetNextKey => 24,
            Self::ObjGetInfoByFd => core::mem::size_of::<BpfObjGetInfoAttr>(),
            Self::ProgLoad => core::mem::size_of::<BpfProgLoadAttr>(),
            Self::LinkCreate => core::mem::size_of::<BpfLinkCreateAttr>(),
            Self::LinkDetach => core::mem::size_of::<BpfLinkDetachAttr>(),
            _ => core::mem::size_of::<BpfAttr>(),
        }
    }
}

/// Rejects non-zero bytes after the command's last attribute field with
/// `EINVAL`, matching Linux `CHECK_ATTR`.
pub fn check_attr_unused_tail(cmd: BpfCmd, attr: &BpfAttr) -> Result<(), LinuxError> {
    attr.check_unused_tail(cmd)
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfMapCreateAttr {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub inner_map_fd: u32,
    pub numa_node: u32,
    pub map_name: [u8; BPF_OBJ_NAME_LEN],
    pub map_ifindex: u32,
    pub btf_fd: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
    pub btf_vmlinux_value_type_id: u32,
    pub map_extra: u64,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfMapElemAttr {
    pub map_fd: u32,
    pub _pad: u32,
    pub key: u64,
    pub value_or_next_key: u64,
    pub flags: u64,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfProgLoadAttr {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: u64,
    pub license: u64,
    pub log_level: u32,
    pub log_size: u32,
    pub log_buf: u64,
    pub kern_version: u32,
    pub prog_flags: u32,
    pub prog_name: [u8; BPF_OBJ_NAME_LEN],
    pub prog_ifindex: u32,
    pub expected_attach_type: u32,
    pub prog_btf_fd: u32,
    pub func_info_rec_size: u32,
    pub func_info: u64,
    pub func_info_cnt: u32,
    pub line_info_rec_size: u32,
    pub line_info: u64,
    pub line_info_cnt: u32,
    pub attach_btf_id: u32,
    pub attach_prog_or_btf_fd: u32,
    pub core_relo_cnt: u32,
    pub fd_array: u64,
    pub core_relos: u64,
    pub core_relo_rec_size: u32,
    pub log_true_size: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfObjPinGetAttr {
    pub pathname: u64,
    pub bpf_fd: u32,
    pub file_flags: u32,
    pub path_fd: i32,
    pub _pad: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfProgAttachDetachAttr {
    pub target_fd: u32,
    pub attach_bpf_fd: u32,
    pub attach_type: u32,
    pub attach_flags: u32,
    pub replace_bpf_fd: u32,
    pub relative_fd: u32,
    pub expected_revision: u64,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfProgTestRunAttr {
    pub prog_fd: u32,
    pub retval: u32,
    pub data_size_in: u32,
    pub data_size_out: u32,
    pub data_in: u64,
    pub data_out: u64,
    pub repeat: u32,
    pub duration: u32,
    pub ctx_size_in: u32,
    pub ctx_size_out: u32,
    pub ctx_in: u64,
    pub ctx_out: u64,
    pub flags: u32,
    pub cpu: u32,
    pub batch_size: u32,
    pub _pad: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfObjGetInfoAttr {
    pub bpf_fd: u32,
    pub info_len: u32,
    pub info: u64,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug)]
pub struct BpfLinkCreateAttr {
    pub prog_fd: u32,
    pub target_fd: u32,
    pub attach_type: u32,
    pub flags: u32,
    pub target_btf_id_or_cookie: u64,
    pub extra: [u8; 40],
}

impl Default for BpfLinkCreateAttr {
    fn default() -> Self {
        Self {
            prog_fd: 0,
            target_fd: 0,
            attach_type: 0,
            flags: 0,
            target_btf_id_or_cookie: 0,
            extra: [0u8; 40],
        }
    }
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfLinkUpdateAttr {
    pub link_fd: u32,
    pub new_prog_fd: u32,
    pub flags: u32,
    pub old_prog_fd: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfLinkDetachAttr {
    pub link_fd: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub union BpfAttr {
    pub map_create: BpfMapCreateAttr,
    pub map_elem: BpfMapElemAttr,
    pub prog_load: BpfProgLoadAttr,
    pub obj_pin_get: BpfObjPinGetAttr,
    pub prog_attach_detach: BpfProgAttachDetachAttr,
    pub prog_test_run: BpfProgTestRunAttr,
    pub info: BpfObjGetInfoAttr,
    pub link_create: BpfLinkCreateAttr,
    pub link_update: BpfLinkUpdateAttr,
    pub link_detach: BpfLinkDetachAttr,
    pub raw: [u8; 144],
}

impl Default for BpfAttr {
    fn default() -> Self {
        Self { raw: [0u8; 144] }
    }
}

impl BpfAttr {
    /// Rejects non-zero bytes after the command's last attribute field with
    /// `EINVAL`, matching Linux `CHECK_ATTR`.
    pub fn check_unused_tail(&self, cmd: BpfCmd) -> Result<(), LinuxError> {
        // SAFETY: every byte of the union is initialized via `raw`.
        let raw = unsafe { &self.raw };
        if raw[cmd.attr_used_size()..].iter().any(|&b| b != 0) {
            Err(LinuxError::EINVAL)
        } else {
            Ok(())
        }
    }
}

const _: () = {
    assert!(core::mem::size_of::<BpfAttr>() == 144);
    assert!(core::mem::align_of::<BpfAttr>() == 8);
    assert!(core::mem::size_of::<BpfMapCreateAttr>() == 72);
    assert!(core::mem::align_of::<BpfMapCreateAttr>() == 8);
    assert!(core::mem::size_of::<BpfMapElemAttr>() == 32);
    assert!(core::mem::align_of::<BpfMapElemAttr>() == 8);
    assert!(core::mem::size_of::<BpfProgLoadAttr>() == 144);
    assert!(core::mem::align_of::<BpfProgLoadAttr>() == 8);
    assert!(core::mem::size_of::<BpfObjPinGetAttr>() == 24);
    assert!(core::mem::align_of::<BpfObjPinGetAttr>() == 8);
    assert!(core::mem::size_of::<BpfProgAttachDetachAttr>() == 32);
    assert!(core::mem::align_of::<BpfProgAttachDetachAttr>() == 8);
    assert!(core::mem::size_of::<BpfObjGetInfoAttr>() == 16);
    assert!(core::mem::align_of::<BpfObjGetInfoAttr>() == 8);
    assert!(core::mem::size_of::<BpfLinkCreateAttr>() == 64);
    assert!(core::mem::align_of::<BpfLinkCreateAttr>() == 8);
    assert!(core::mem::size_of::<BpfLinkUpdateAttr>() == 16);
    assert!(core::mem::align_of::<BpfLinkUpdateAttr>() == 8);
    assert!(core::mem::size_of::<BpfLinkDetachAttr>() == 4);
    assert!(core::mem::align_of::<BpfLinkDetachAttr>() == 4);
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BpfPermissions {
    pub is_root: bool,
    pub has_cap_sys_admin: bool,
    pub has_cap_bpf: bool,
}

impl BpfPermissions {
    pub const fn new(is_root: bool, has_cap_sys_admin: bool, has_cap_bpf: bool) -> Self {
        Self {
            is_root,
            has_cap_sys_admin,
            has_cap_bpf,
        }
    }

    pub const fn is_authorized(self) -> bool {
        self.is_root || self.has_cap_sys_admin || self.has_cap_bpf
    }
}

pub fn validate_bpf_attr_size(size: usize, min_size: usize) -> Result<usize, LinuxError> {
    if size > BPF_MAX_ATTR_SIZE {
        return Err(LinuxError::E2BIG);
    }
    if size < min_size {
        return Err(LinuxError::EINVAL);
    }
    Ok(size)
}

pub fn check_trailing_zero(tail: &[u8]) -> Result<(), LinuxError> {
    if tail.iter().any(|&b| b != 0) {
        Err(LinuxError::E2BIG)
    } else {
        Ok(())
    }
}

pub fn validate_user_attr_range(attr: usize, size: usize) -> Result<(), LinuxError> {
    if attr == 0 && size > 0 {
        return Err(LinuxError::EFAULT);
    }
    let Some(end) = attr.checked_add(size) else {
        return Err(LinuxError::EFAULT);
    };
    #[cfg(target_os = "none")]
    {
        let _ = end;
        pulse_core::task::uaccess::validate_user_range(attr, size)
            .map_err(|_| LinuxError::EFAULT)?;
    }
    #[cfg(not(target_os = "none"))]
    {
        if attr < 0x1000 || end < attr {
            return Err(LinuxError::EFAULT);
        }
    }
    Ok(())
}

pub fn check_bpf_permission(
    is_root: bool,
    has_cap_sys_admin: bool,
    has_cap_bpf: bool,
) -> Result<(), LinuxError> {
    let perms = BpfPermissions::new(is_root, has_cap_sys_admin, has_cap_bpf);
    if perms.is_authorized() {
        Ok(())
    } else {
        Err(LinuxError::EPERM)
    }
}

pub fn validate_bpf_syscall<F>(
    perms: BpfPermissions,
    cmd_raw: i32,
    attr_addr: usize,
    size: usize,
    mut read_user: F,
) -> Result<(BpfCmd, BpfAttr), LinuxError>
where
    F: FnMut(usize, &mut [u8]) -> Result<(), LinuxError>,
{
    // 1. Permission check precedence: non-authorized callers receive EPERM
    // without reading user pointers or allocating objects.
    if !perms.is_authorized() {
        return Err(LinuxError::EPERM);
    }

    // 2. Command check precedence: unknown command returns EINVAL.
    if cmd_raw < 0 {
        return Err(LinuxError::EINVAL);
    }
    let cmd = BpfCmd::from_raw(cmd_raw as u32)?;

    // 3. Size boundary checks:
    // Size > 4096 returns E2BIG.
    // Size < min_attr_size returns EINVAL.
    validate_bpf_attr_size(size, cmd.min_attr_size())?;

    // 4. Pointer range check:
    // Null pointer or arithmetic overflow returns EFAULT.
    if attr_addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    if attr_addr.checked_add(size).is_none() {
        return Err(LinuxError::EFAULT);
    }

    // 5. Copy base attributes up to sizeof(BpfAttr).
    let mut attr = BpfAttr::default();
    let copy_size = core::cmp::min(size, core::mem::size_of::<BpfAttr>());
    let raw_slice = unsafe {
        core::slice::from_raw_parts_mut(
            &mut attr as *mut BpfAttr as *mut u8,
            copy_size,
        )
    };
    read_user(attr_addr, raw_slice)?;

    // 6. If size > sizeof(BpfAttr), ensure trailing bytes are all zero.
    let attr_struct_size = core::mem::size_of::<BpfAttr>();
    if size > attr_struct_size {
        let mut check_offset = attr_struct_size;
        let mut tail_buf = [0u8; 128];
        while check_offset < size {
            let chunk = core::cmp::min(128, size - check_offset);
            let tail_addr = attr_addr
                .checked_add(check_offset)
                .ok_or(LinuxError::EFAULT)?;
            read_user(tail_addr, &mut tail_buf[..chunk])?;
            check_trailing_zero(&tail_buf[..chunk])?;
            check_offset += chunk;
        }
    }

    Ok((cmd, attr))
}
