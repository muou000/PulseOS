//! `io_uring` 预注册资源表（Fixed Buffers / Fixed Files）与窗口边界纯逻辑。

use alloc::{sync::Arc, vec::Vec};

use axerrno::LinuxError;

/// 用户页大小（4 KiB）。
pub const USER_PAGE_SIZE: usize = 4096;

/// 单个滑动钉住窗口允许的最大用户缓冲字节数（64 KiB）。
pub const MAX_PIN_WINDOW_BYTES: usize = 64 * 1024;

/// 单个滑动钉住窗口允许的最大物理页片段数（32 个页片段）。
pub const MAX_PIN_WINDOW_FRAGMENTS: usize = 32;

/// 单个 `io_uring` 实例允许预注册的固定缓冲区最大槽位数。
pub const MAX_FIXED_BUFFERS: usize = 1024;

/// 单个固定缓冲区允许的最大字节长度（1 GiB）。
pub const MAX_FIXED_BUFFER_LEN: usize = 1024 * 1024 * 1024;

/// 单个 `io_uring` 实例允许预注册的固定缓冲区总页数上限（65536 页 = 256 MiB）。
pub const MAX_RING_FIXED_BUFFER_PAGES: usize = 65_536;

/// 单个 `io_uring` 实例允许预注册的固定文件描述符最大槽位数。
pub const MAX_FIXED_FILES: usize = 65_536;

/// 固定文件槽位中的空洞哨兵值（对应 Linux `-1`）。
pub const FIXED_FILE_EMPTY: i32 = -1;

/// 一段用户态 I/O 缓冲描述符（地址与长度）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserIoSegment {
    pub addr: usize,
    pub len: usize,
}

impl UserIoSegment {
    #[inline]
    pub const fn new(addr: usize, len: usize) -> Self {
        Self { addr, len }
    }
}

/// 累计用户缓冲段总长度，溢出返回 `-EINVAL`。
pub fn checked_total_len(segments: &[UserIoSegment]) -> Result<usize, LinuxError> {
    let mut total = 0usize;
    for seg in segments {
        total = total.checked_add(seg.len).ok_or(LinuxError::EINVAL)?;
    }
    Ok(total)
}

/// Validates `O_DIRECT` user buffer addresses and lengths against `block_size`.
pub fn validate_direct_io_buffers(
    segments: &[UserIoSegment],
    block_size: usize,
) -> Result<(), LinuxError> {
    if block_size == 0 {
        return Err(LinuxError::EINVAL);
    }
    for segment in segments {
        if !segment.addr.is_multiple_of(block_size) || !segment.len.is_multiple_of(block_size) {
            return Err(LinuxError::EINVAL);
        }
    }
    Ok(())
}

/// Validates an `O_DIRECT` file offset against `block_size`.
#[inline]
pub fn validate_direct_io_offset(offset: u64, block_size: usize) -> Result<(), LinuxError> {
    if block_size == 0 || !offset.is_multiple_of(block_size as u64) {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

/// Validates `O_DIRECT` file offset and user buffer alignment against `block_size`.
pub fn validate_direct_io(
    segments: &[UserIoSegment],
    offset: u64,
    block_size: usize,
) -> Result<(), LinuxError> {
    validate_direct_io_offset(offset, block_size)?;
    validate_direct_io_buffers(segments, block_size)
}

/// 计算 `[addr, addr + len)` 横跨的 4 KiB 用户页数。
pub fn page_count_for_range(addr: usize, len: usize) -> Result<usize, LinuxError> {
    if len == 0 {
        return Ok(0);
    }
    let end = addr.checked_add(len).ok_or(LinuxError::EFAULT)?;
    let start_page = addr / USER_PAGE_SIZE;
    let end_page = (end - 1) / USER_PAGE_SIZE;
    Ok(end_page - start_page + 1)
}

/// 判断给定段列表是否可由单个 `PinnedUserBuffers` 窗口完整容纳。
pub fn fits_single_pin_window(segments: &[UserIoSegment]) -> bool {
    let mut total_bytes = 0usize;
    let mut total_fragments = 0usize;

    for seg in segments {
        if seg.len == 0 {
            continue;
        }
        let Ok(pages) = page_count_for_range(seg.addr, seg.len) else {
            return false;
        };
        let Some(next_bytes) = total_bytes.checked_add(seg.len) else {
            return false;
        };
        let Some(next_fragments) = total_fragments.checked_add(pages) else {
            return false;
        };
        if next_bytes > MAX_PIN_WINDOW_BYTES || next_fragments > MAX_PIN_WINDOW_FRAGMENTS {
            return false;
        }
        total_bytes = next_bytes;
        total_fragments = next_fragments;
    }

    true
}

/// 校验结果：经过合法性检查后的固定缓冲区注册计划。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedFixedBuffersPlan {
    pub total_pages: usize,
    pub charged_bytes: usize,
    pub non_empty_slots: usize,
}

/// 校验待预注册的一组固定缓冲区描述符。
pub fn validate_fixed_buffer_specs<F>(
    specs: &[UserIoSegment],
    is_valid_user_range: F,
) -> Result<ValidatedFixedBuffersPlan, LinuxError>
where
    F: Fn(usize, usize) -> bool,
{
    if specs.is_empty() || specs.len() > MAX_FIXED_BUFFERS {
        return Err(LinuxError::EINVAL);
    }

    let mut total_pages = 0usize;
    let mut non_empty_slots = 0usize;

    for spec in specs {
        if spec.len > MAX_FIXED_BUFFER_LEN {
            return Err(LinuxError::EINVAL);
        }
        if spec.len == 0 {
            continue;
        }
        if !is_valid_user_range(spec.addr, spec.len) {
            return Err(LinuxError::EFAULT);
        }
        let pages = page_count_for_range(spec.addr, spec.len)?;
        total_pages = total_pages
            .checked_add(pages)
            .ok_or(LinuxError::ENOMEM)?;
        if total_pages > MAX_RING_FIXED_BUFFER_PAGES {
            return Err(LinuxError::ENOMEM);
        }
        non_empty_slots += 1;
    }

    if non_empty_slots == 0 {
        return Err(LinuxError::EINVAL);
    }

    let charged_bytes = total_pages
        .checked_mul(USER_PAGE_SIZE)
        .ok_or(LinuxError::ENOMEM)?;

    Ok(ValidatedFixedBuffersPlan {
        total_pages,
        charged_bytes,
        non_empty_slots,
    })
}

/// 单个预注册固定缓冲区槽位。
#[derive(Debug)]
pub struct FixedBufferSlot<P> {
    pub user_base: usize,
    pub len: usize,
    pub writable: bool,
    pub pages: Option<P>,
}

impl<P> FixedBufferSlot<P> {
    #[inline]
    pub const fn empty(user_base: usize) -> Self {
        Self {
            user_base,
            len: 0,
            writable: false,
            pages: None,
        }
    }

    #[inline]
    pub const fn with_pages(user_base: usize, len: usize, writable: bool, pages: P) -> Self {
        Self {
            user_base,
            len,
            writable,
            pages: Some(pages),
        }
    }
}

/// 已解析的固定缓冲区切片定位信息。
#[derive(Debug)]
pub struct FixedBufferSlice<P> {
    pub slot: Arc<FixedBufferSlot<P>>,
    pub offset: usize,
    pub len: usize,
}

/// 一张完整注册的固定缓冲区表，由 `Arc<FixedBufferSlot<P>>` 为在途请求续命。
#[derive(Debug)]
pub struct FixedBufferTable<P> {
    slots: Vec<Arc<FixedBufferSlot<P>>>,
    charged_bytes: usize,
}

impl<P> FixedBufferTable<P> {
    pub fn new(slots: Vec<Arc<FixedBufferSlot<P>>>, charged_bytes: usize) -> Self {
        Self {
            slots,
            charged_bytes,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    #[inline]
    pub const fn charged_bytes(&self) -> usize {
        self.charged_bytes
    }

    /// 按 `buf_index` 与 `[addr, addr + len)` 解析槽位切片，并对只读映射拒绝写入请求。
    pub fn resolve_slice(
        &self,
        buf_index: u16,
        addr: u64,
        len: u32,
        require_write: bool,
    ) -> Result<FixedBufferSlice<P>, LinuxError> {
        let slot = self
            .slots
            .get(buf_index as usize)
            .ok_or(LinuxError::EFAULT)?;
        let req_addr = usize::try_from(addr).map_err(|_| LinuxError::EFAULT)?;
        let req_len = len as usize;
        let req_end = req_addr.checked_add(req_len).ok_or(LinuxError::EFAULT)?;
        let slot_end = slot
            .user_base
            .checked_add(slot.len)
            .ok_or(LinuxError::EFAULT)?;
        if req_addr < slot.user_base || req_end > slot_end {
            return Err(LinuxError::EFAULT);
        }
        if require_write && slot.len > 0 && !slot.writable {
            return Err(LinuxError::EFAULT);
        }
        Ok(FixedBufferSlice {
            slot: Arc::clone(slot),
            offset: req_addr - slot.user_base,
            len: req_len,
        })
    }
}

/// `io_uring` 固定缓冲区注册表状态机。
#[derive(Debug)]
pub struct FixedBufferRegistry<P> {
    table: Option<FixedBufferTable<P>>,
}

impl<P> Default for FixedBufferRegistry<P> {
    fn default() -> Self {
        Self { table: None }
    }
}

impl<P> FixedBufferRegistry<P> {
    pub const fn new() -> Self {
        Self { table: None }
    }

    #[inline]
    pub fn is_registered(&self) -> bool {
        self.table.is_some()
    }

    pub fn check_can_register(&self, nr_args: usize) -> Result<(), LinuxError> {
        if self.table.is_some() {
            return Err(LinuxError::EBUSY);
        }
        if nr_args == 0 || nr_args > MAX_FIXED_BUFFERS {
            return Err(LinuxError::EINVAL);
        }
        Ok(())
    }

    pub fn install(&mut self, table: FixedBufferTable<P>) -> Result<(), (LinuxError, FixedBufferTable<P>)> {
        if self.table.is_some() {
            return Err((LinuxError::EBUSY, table));
        }
        self.table = Some(table);
        Ok(())
    }

    /// 校验并拆出已注册表；调用方负责在锁外归还 `charged_bytes` 并 drop 表。
    pub fn unregister(&mut self, arg: usize, nr_args: u32) -> Result<FixedBufferTable<P>, LinuxError> {
        if arg != 0 || nr_args != 0 {
            return Err(LinuxError::EINVAL);
        }
        self.table.take().ok_or(LinuxError::ENXIO)
    }

    #[inline]
    pub fn take_for_drop(&mut self) -> Option<FixedBufferTable<P>> {
        self.table.take()
    }

    pub fn resolve_slice(
        &self,
        buf_index: u16,
        addr: u64,
        len: u32,
        require_write: bool,
    ) -> Result<FixedBufferSlice<P>, LinuxError> {
        let table = self.table.as_ref().ok_or(LinuxError::EFAULT)?;
        table.resolve_slice(buf_index, addr, len, require_write)
    }
}

/// `io_uring` 固定文件表状态机。
#[derive(Debug)]
pub struct FixedFileRegistry<E> {
    slots: Option<Vec<Option<E>>>,
}

impl<E> Default for FixedFileRegistry<E> {
    fn default() -> Self {
        Self { slots: None }
    }
}

impl<E: Clone> FixedFileRegistry<E> {
    pub const fn new() -> Self {
        Self { slots: None }
    }

    #[inline]
    pub fn is_registered(&self) -> bool {
        self.slots.is_some()
    }

    #[inline]
    pub fn len(&self) -> Option<usize> {
        self.slots.as_ref().map(Vec::len)
    }

    pub fn check_can_register(&self, nr_args: usize) -> Result<(), LinuxError> {
        if self.slots.is_some() {
            return Err(LinuxError::EBUSY);
        }
        if nr_args == 0 {
            return Err(LinuxError::EINVAL);
        }
        if nr_args > MAX_FIXED_FILES {
            return Err(LinuxError::EMFILE);
        }
        Ok(())
    }

    /// 解析单个用户态传入的文件描述符（`-1` 允许作为空槽，其它负数报错 `-EBADF`）。
    pub fn resolve_slot_fd<F>(fd: i32, resolve_fd: &mut F) -> Result<Option<E>, LinuxError>
    where
        F: FnMut(usize) -> Result<E, LinuxError>,
    {
        if fd == FIXED_FILE_EMPTY {
            return Ok(None);
        }
        if fd < 0 {
            return Err(LinuxError::EBADF);
        }
        resolve_fd(fd as usize).map(Some)
    }

    pub fn install(&mut self, slots: Vec<Option<E>>) -> Result<(), (LinuxError, Vec<Option<E>>)> {
        if self.slots.is_some() {
            return Err((LinuxError::EBUSY, slots));
        }
        self.slots = Some(slots);
        Ok(())
    }

    /// 校验并拆出已注册文件表；调用方负责在 `SpinNoIrq` 锁外 drop。
    pub fn unregister(&mut self, arg: usize, nr_args: u32) -> Result<Vec<Option<E>>, LinuxError> {
        if arg != 0 || nr_args != 0 {
            return Err(LinuxError::EINVAL);
        }
        self.slots.take().ok_or(LinuxError::ENXIO)
    }

    #[inline]
    pub fn take_for_drop(&mut self) -> Option<Vec<Option<E>>> {
        self.slots.take()
    }

    /// 校验更新范围，返回需要写入的 `Vec` 起始下标。
    pub fn validate_update(&self, offset: u32, nr_args: u32, resv: u32) -> Result<usize, LinuxError> {
        if resv != 0 || nr_args == 0 {
            return Err(LinuxError::EINVAL);
        }
        let slots = self.slots.as_ref().ok_or(LinuxError::ENXIO)?;
        let start = offset as usize;
        let count = nr_args as usize;
        let end = start.checked_add(count).ok_or(LinuxError::EINVAL)?;
        if end > slots.len() {
            return Err(LinuxError::EINVAL);
        }
        Ok(start)
    }

    /// 将已顺序解析完成的槽位写入 `slots[offset..]`，并返回 `(Result<done, first_err>, replaced)`。
    pub fn apply_resolved_update(
        &mut self,
        offset: usize,
        resolved: Vec<Option<E>>,
        first_err: Option<LinuxError>,
    ) -> (Result<usize, LinuxError>, Vec<Option<E>>) {
        let Some(slots) = self.slots.as_mut() else {
            return (Err(LinuxError::ENXIO), resolved);
        };
        let Some(end) = offset.checked_add(resolved.len()) else {
            return (Err(LinuxError::EINVAL), resolved);
        };
        if end > slots.len() {
            return (Err(LinuxError::EINVAL), resolved);
        }

        let mut replaced = Vec::with_capacity(resolved.len());
        let mut done = 0usize;
        for (idx, next_slot) in resolved.into_iter().enumerate() {
            let old = core::mem::replace(&mut slots[offset + idx], next_slot);
            replaced.push(old);
            done += 1;
        }

        let res = if done > 0 {
            Ok(done)
        } else if let Some(err) = first_err {
            Err(err)
        } else {
            Ok(0)
        };
        (res, replaced)
    }

    pub fn get_cloned(&self, index: u32) -> Result<E, LinuxError> {
        let slots = self.slots.as_ref().ok_or(LinuxError::EBADF)?;
        let slot = slots.get(index as usize).ok_or(LinuxError::EBADF)?;
        slot.as_ref().cloned().ok_or(LinuxError::EBADF)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct DropCounter(Arc<AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn always_user_range(_ptr: usize, _len: usize) -> bool {
        true
    }

    #[test]
    fn fits_single_pin_window_respects_byte_and_fragment_limits() {
        assert!(fits_single_pin_window(&[]));
        assert!(fits_single_pin_window(&[UserIoSegment::new(0x1000, MAX_PIN_WINDOW_BYTES)]));
        assert!(!fits_single_pin_window(&[UserIoSegment::new(
            0x1000,
            MAX_PIN_WINDOW_BYTES + 1,
        )]));

        // 16 scattered 1-byte segments across distinct pages fit within 32 fragments,
        // while 33 distinct pages exceed MAX_PIN_WINDOW_FRAGMENTS.
        let ok_segs: Vec<_> = (0..MAX_PIN_WINDOW_FRAGMENTS)
            .map(|i| UserIoSegment::new(0x10_000 + i * USER_PAGE_SIZE, 1))
            .collect();
        assert!(fits_single_pin_window(&ok_segs));

        let too_many_frags: Vec<_> = (0..=MAX_PIN_WINDOW_FRAGMENTS)
            .map(|i| UserIoSegment::new(0x10_000 + i * USER_PAGE_SIZE, 1))
            .collect();
        assert!(!fits_single_pin_window(&too_many_frags));

        // Zero-length segments do not exhaust window budget.
        let with_empty = vec![
            UserIoSegment::new(0, 0),
            UserIoSegment::new(0x1000, MAX_PIN_WINDOW_BYTES),
            UserIoSegment::new(0, 0),
        ];
        assert!(fits_single_pin_window(&with_empty));
    }

    #[test]
    fn validate_fixed_buffer_specs_enforces_limits_and_errors() {
        assert_eq!(
            validate_fixed_buffer_specs(&[], always_user_range),
            Err(LinuxError::EINVAL)
        );
        let too_many = vec![UserIoSegment::new(0x1000, 4096); MAX_FIXED_BUFFERS + 1];
        assert_eq!(
            validate_fixed_buffer_specs(&too_many, always_user_range),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_fixed_buffer_specs(
                &[UserIoSegment::new(0x1000, MAX_FIXED_BUFFER_LEN + 1)],
                always_user_range
            ),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_fixed_buffer_specs(
                &[UserIoSegment::new(0x1000, 0), UserIoSegment::new(0x2000, 0)],
                always_user_range
            ),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_fixed_buffer_specs(&[UserIoSegment::new(0x1000, 4096)], |_, _| false),
            Err(LinuxError::EFAULT)
        );

        // Partial empty slot alongside non-empty slot succeeds.
        let plan = validate_fixed_buffer_specs(
            &[UserIoSegment::new(0, 0), UserIoSegment::new(0x1000, 4096)],
            always_user_range,
        )
        .unwrap();
        assert_eq!(plan.total_pages, 1);
        assert_eq!(plan.charged_bytes, USER_PAGE_SIZE);
        assert_eq!(plan.non_empty_slots, 1);

        // Exceeding 65536 pages (e.g. two 200 MiB buffers = 400 MiB > 256 MiB) yields -ENOMEM.
        let over_ring_cap = vec![
            UserIoSegment::new(0x1_0000_0000, 200 * 1024 * 1024),
            UserIoSegment::new(0x2_0000_0000, 200 * 1024 * 1024),
        ];
        assert_eq!(
            validate_fixed_buffer_specs(&over_ring_cap, always_user_range),
            Err(LinuxError::ENOMEM)
        );
    }

    #[test]
    fn fixed_buffer_registry_lifecycle_ro_and_inflight_keepalive() {
        let mut reg = FixedBufferRegistry::new();
        assert_eq!(reg.check_can_register(0), Err(LinuxError::EINVAL));
        assert_eq!(
            reg.check_can_register(MAX_FIXED_BUFFERS + 1),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(reg.unregister(0, 0).err(), Some(LinuxError::ENXIO));

        let drops = Arc::new(AtomicUsize::new(0));
        let rw_slot = Arc::new(FixedBufferSlot::with_pages(
            0x2000,
            4096,
            true,
            DropCounter(drops.clone()),
        ));
        let ro_slot = Arc::new(FixedBufferSlot::with_pages(
            0x4000,
            4096,
            false,
            DropCounter(drops.clone()),
        ));
        let empty_slot = Arc::new(FixedBufferSlot::empty(0));

        let table = FixedBufferTable::new(vec![rw_slot, ro_slot, empty_slot], 8192);
        reg.install(table).unwrap();

        assert_eq!(reg.check_can_register(1), Err(LinuxError::EBUSY));
        assert_eq!(reg.unregister(1, 0).err(), Some(LinuxError::EINVAL));
        assert_eq!(reg.unregister(0, 1).err(), Some(LinuxError::EINVAL));

        // RW slot allows both READ_FIXED (require_write=true) and WRITE_FIXED (require_write=false).
        let inflight_rw = reg.resolve_slice(0, 0x2100, 128, true).unwrap();
        assert_eq!(inflight_rw.offset, 0x100);
        assert_eq!(inflight_rw.len, 128);

        // RO slot allows WRITE_FIXED (require_write=false) and rejects READ_FIXED (require_write=true).
        assert!(reg.resolve_slice(1, 0x4000, 64, false).is_ok());
        assert_eq!(
            reg.resolve_slice(1, 0x4000, 64, true).err(),
            Some(LinuxError::EFAULT)
        );

        // Out-of-bounds, bad buf_index, and non-zero length in empty slot return -EFAULT.
        assert_eq!(
            reg.resolve_slice(0, 0x2f00, 512, false).err(),
            Some(LinuxError::EFAULT)
        );
        assert_eq!(
            reg.resolve_slice(3, 0x2000, 4, false).err(),
            Some(LinuxError::EFAULT)
        );
        assert_eq!(
            reg.resolve_slice(2, 0, 1, false).err(),
            Some(LinuxError::EFAULT)
        );

        // Unregistering drops unpinned RO slot immediately, while `inflight_rw` keeps slot 0 alive.
        let old_table = reg.unregister(0, 0).unwrap();
        assert_eq!(old_table.charged_bytes(), 8192);
        drop(old_table);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(inflight_rw);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn fixed_file_registry_supports_sparse_partial_update_and_unregister() {
        let mut reg: FixedFileRegistry<u32> = FixedFileRegistry::new();
        assert_eq!(reg.check_can_register(0), Err(LinuxError::EINVAL));
        assert_eq!(
            reg.check_can_register(MAX_FIXED_FILES + 1),
            Err(LinuxError::EMFILE)
        );
        assert_eq!(reg.validate_update(0, 1, 0), Err(LinuxError::ENXIO));
        assert_eq!(reg.unregister(0, 0), Err(LinuxError::ENXIO));

        let r0 = FixedFileRegistry::<u32>::resolve_slot_fd(-1, &mut |_| Err(LinuxError::EBADF));
        assert_eq!(r0, Ok(None));
        let r1 = FixedFileRegistry::resolve_slot_fd(-2, &mut |_| Ok(99u32));
        assert_eq!(r1, Err(LinuxError::EBADF));
        let r2 = FixedFileRegistry::resolve_slot_fd(7, &mut |fd| Ok(fd as u32 + 10));
        assert_eq!(r2, Ok(Some(17)));

        reg.install(vec![Some(10), None, Some(30)]).unwrap();
        assert_eq!(reg.check_can_register(1), Err(LinuxError::EBUSY));
        assert_eq!(reg.get_cloned(0), Ok(10));
        assert_eq!(reg.get_cloned(1), Err(LinuxError::EBADF));
        assert_eq!(reg.get_cloned(9), Err(LinuxError::EBADF));

        assert_eq!(reg.validate_update(0, 1, 1), Err(LinuxError::EINVAL));
        assert_eq!(reg.validate_update(2, 2, 0), Err(LinuxError::EINVAL));
        assert_eq!(reg.validate_update(1, 2, 0), Ok(1));

        // Partial success stops at first error and returns `done = 1`.
        let (res, replaced) = reg.apply_resolved_update(1, vec![Some(20)], Some(LinuxError::EBADF));
        assert_eq!(res, Ok(1));
        assert_eq!(replaced, vec![None]);
        assert_eq!(reg.get_cloned(1), Ok(20));

        // Error on first item returns Err(EBADF).
        let (res2, replaced2) = reg.apply_resolved_update(0, Vec::new(), Some(LinuxError::EBADF));
        assert_eq!(res2, Err(LinuxError::EBADF));
        assert!(replaced2.is_empty());

        let old = reg.unregister(0, 0).unwrap();
        assert_eq!(old, vec![Some(10), Some(20), Some(30)]);
        assert_eq!(reg.get_cloned(0), Err(LinuxError::EBADF));
    }

    #[test]
    fn direct_io_validation_enforces_alignment_for_offsets_and_segments() {
        let ok = [
            UserIoSegment::new(0x2000, 4096),
            UserIoSegment::new(0x4000, 512),
        ];
        assert_eq!(validate_direct_io(&ok, 4096, 512), Ok(()));
        assert_eq!(validate_direct_io(&ok, 1u64 << 33, 512), Ok(()));

        // Zero block size or unaligned offset -> -EINVAL
        assert_eq!(validate_direct_io(&ok, 0, 0), Err(LinuxError::EINVAL));
        assert_eq!(validate_direct_io(&ok, 511, 512), Err(LinuxError::EINVAL));

        // Unaligned user buffer address or length -> -EINVAL
        let bad_addr = [UserIoSegment::new(0x2001, 512)];
        assert_eq!(validate_direct_io(&bad_addr, 0, 512), Err(LinuxError::EINVAL));
        let bad_len = [UserIoSegment::new(0x2000, 513)];
        assert_eq!(validate_direct_io(&bad_len, 0, 512), Err(LinuxError::EINVAL));
    }
}
