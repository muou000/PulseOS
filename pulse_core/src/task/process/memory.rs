use super::*;
use crate::task;

impl Process {
    pub fn validate_user_range(&self, user_addr: usize, len: usize) -> AxResult<()> {
        if len == 0 {
            return Ok(());
        }

        let user_end = user_addr.checked_add(len).ok_or(AxError::BadAddress)?;
        let user_space_end = USER_SPACE_BASE
            .checked_add(USER_SPACE_SIZE)
            .ok_or(AxError::BadAddress)?;
        if user_addr < USER_SPACE_BASE || user_end > user_space_end {
            return Err(AxError::BadAddress);
        }
        Ok(())
    }
}

impl Process {
    pub fn brk_state_handle(&self) -> Arc<Mutex<BrkState>> {
        self.brk_state.read().clone()
    }

    pub fn get_heap_top(&self) -> usize {
        self.brk_state_handle().lock().current()
    }

    pub fn reset_brk_state(
        &self,
        start: usize,
        current: usize,
        start_data: usize,
        end_data: usize,
    ) {
        *self.brk_state.write() = Arc::new(Mutex::new(BrkState::new(
            start, current, start_data, end_data,
        )));
    }

    pub fn try_fault_in_user_range(
        &self,
        user_addr: usize,
        len: usize,
        access: MappingFlags,
    ) -> AxResult<()> {
        self.validate_user_range(user_addr, len)?;
        if len == 0 {
            return Ok(());
        }
        let end = user_addr.checked_add(len).ok_or(AxError::BadAddress)?;
        let start_page = VirtAddr::from(user_addr).align_down_4k();
        let end_page = VirtAddr::from(end).align_up_4k();
        let access = access | MappingFlags::USER;

        let aspace_handle = self.aspace_handle();
        let mut page = start_page;
        while page < end_page {
            {
                let aspace = aspace_handle.read();
                while page < end_page {
                    let already_resident = aspace
                        .query_vaddr(page)
                        .is_ok_and(|(paddr, flags, _)| {
                            paddr.as_usize() != 0 && flags.contains(access)
                        });
                    if !already_resident {
                        break;
                    }
                    page += PAGE_SIZE_4K;
                }
            }

            if page >= end_page {
                break;
            }
            if !self.resolve_page_fault(&aspace_handle, page, access)? {
                return Err(AxError::BadAddress);
            }
            page += PAGE_SIZE_4K;
        }
        Ok(())
    }

    pub fn read_user_bytes(&self, user_addr: usize, bytes: &mut [u8]) -> AxResult<()> {
        if self.read_user_bytes_partial(user_addr, bytes)? == bytes.len() {
            Ok(())
        } else {
            Err(AxError::BadAddress)
        }
    }

    pub fn write_user_bytes(&self, user_addr: usize, bytes: &[u8]) -> AxResult<()> {
        if self.write_user_bytes_partial(user_addr, bytes)? == bytes.len() {
            Ok(())
        } else {
            Err(AxError::BadAddress)
        }
    }

    pub fn read_user_bytes_partial(&self, user_addr: usize, bytes: &mut [u8]) -> AxResult<usize> {
        self.validate_user_range(user_addr, bytes.len())?;
        if task::current_process().is_ok_and(|current| core::ptr::eq(current.as_ref(), self)) {
            return task::uaccess::copy_from_user_partial(bytes, user_addr);
        }

        let start = VirtAddr::from(user_addr);
        let aspace_handle = self.aspace_handle();
        if aspace_handle.read().read(start, bytes).is_ok() {
            return Ok(bytes.len());
        }
        self.try_fault_in_user_range(user_addr, bytes.len(), MappingFlags::READ)?;
        aspace_handle
            .read()
            .read(start, bytes)
            .map(|()| bytes.len())
            .map_err(AxError::from)
    }

    pub fn write_user_bytes_partial(&self, user_addr: usize, bytes: &[u8]) -> AxResult<usize> {
        self.validate_user_range(user_addr, bytes.len())?;
        if task::current_process().is_ok_and(|current| core::ptr::eq(current.as_ref(), self)) {
            return task::uaccess::copy_to_user_partial(user_addr, bytes);
        }

        let start = VirtAddr::from(user_addr);
        let aspace_handle = self.aspace_handle();
        if aspace_handle.read().write(start, bytes).is_ok() {
            return Ok(bytes.len());
        }
        self.try_fault_in_user_range(user_addr, bytes.len(), MappingFlags::WRITE)?;
        aspace_handle
            .read()
            .write(start, bytes)
            .map(|()| bytes.len())
            .map_err(AxError::from)
    }

    pub fn aspace_handle(&self) -> Arc<AddressSpaceLock> {
        self.aspace.read().clone()
    }

    pub fn replace_aspace_handle(
        &self,
        new_aspace: Arc<AddressSpaceLock>,
    ) -> Arc<AddressSpaceLock> {
        let mut slot = self.aspace.write();
        core::mem::replace(&mut *slot, new_aspace)
    }

    pub fn page_table_root(&self) -> PhysAddr {
        self.aspace_handle().read().page_table_root()
    }

    pub fn asid(&self) -> usize {
        self.aspace_handle().read().asid()
    }

    pub fn read_user_u32(&self, user_addr: usize) -> AxResult<u32> {
        let mut bytes = [0u8; core::mem::size_of::<u32>()];
        self.read_user_bytes(user_addr, &mut bytes)?;
        Ok(u32::from_ne_bytes(bytes))
    }

    pub fn read_user_usize(&self, user_addr: usize) -> AxResult<usize> {
        let mut bytes = [0u8; core::mem::size_of::<usize>()];
        self.read_user_bytes(user_addr, &mut bytes)?;
        Ok(usize::from_ne_bytes(bytes))
    }

    pub fn read_user_isize(&self, user_addr: usize) -> AxResult<isize> {
        let mut bytes = [0u8; core::mem::size_of::<isize>()];
        self.read_user_bytes(user_addr, &mut bytes)?;
        Ok(isize::from_ne_bytes(bytes))
    }

    pub fn write_user_u32(&self, user_addr: usize, value: u32) -> AxResult<()> {
        self.write_user_bytes(user_addr, &value.to_ne_bytes())
    }

    pub fn write_user_i32(&self, user_addr: usize, value: i32) -> AxResult<()> {
        self.write_user_bytes(user_addr, &value.to_ne_bytes())
    }

    pub fn write_user_usize(&self, user_addr: usize, value: usize) -> AxResult<()> {
        self.write_user_bytes(user_addr, &value.to_ne_bytes())
    }
}

impl Process {
    pub fn is_user_range(&self, addr: usize, len: usize) -> bool {
        self.validate_user_range(addr, len).is_ok()
    }

    pub fn align_user_range(
        &self,
        addr: usize,
        len: usize,
    ) -> Result<(usize, usize), axerrno::LinuxError> {
        if len == 0 {
            return Ok((addr & !(4096 - 1), 0));
        }
        let aligned_addr = addr & !(4096 - 1);
        let end = addr.checked_add(len).ok_or(axerrno::LinuxError::EINVAL)?;
        let aligned_end = (end
            .checked_add(4096 - 1)
            .ok_or(axerrno::LinuxError::EINVAL)?)
            & !(4096 - 1);
        if aligned_end < aligned_addr {
            return Err(axerrno::LinuxError::EINVAL);
        }
        let aligned_len = aligned_end - aligned_addr;
        if !self.is_user_range(aligned_addr, aligned_len) {
            return Err(axerrno::LinuxError::EINVAL);
        }
        Ok((aligned_addr, aligned_len))
    }

    pub fn is_mapped_range(&self, addr: usize, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let aspace_handle = self.aspace_handle();
        let aspace = aspace_handle.read();
        aspace.can_access_range(VirtAddr::from(addr), len, MappingFlags::empty())
    }

    pub fn prefault_user_range(&self, addr: usize, len: usize) -> Result<(), axerrno::LinuxError> {
        if len == 0 {
            return Ok(());
        }
        let aspace_handle = self.aspace_handle();
        let start = VirtAddr::from(addr);
        if !aspace_handle
            .read()
            .can_access_range(start, len, MappingFlags::empty())
        {
            return Err(axerrno::LinuxError::ENOMEM);
        }
        self.try_fault_in_user_range(addr, len, MappingFlags::empty())
            .map_err(|_| axerrno::LinuxError::ENOMEM)
    }

    pub fn lock_mapped_range(&self, addr: usize, len: usize) -> Result<(), axerrno::LinuxError> {
        if len == 0 {
            return Ok(());
        }
        self.prefault_user_range(addr, len)?;
        let privileged = self.is_root_user();
        self.memlock_try_lock_range(addr, len, privileged)
            .map_err(|e| match e {
                AxError::NoMemory => axerrno::LinuxError::ENOMEM,
                _ => axerrno::LinuxError::EINVAL,
            })?;
        Ok(())
    }

    pub fn lock_all_current_mappings(&self) -> Result<(), axerrno::LinuxError> {
        let user_area_count = {
            let mut count = 0usize;
            let aspace_handle = self.aspace_handle();
            let aspace = aspace_handle.read();
            aspace.for_each_area(|_, _, flags| {
                if flags.contains(MappingFlags::USER) {
                    count = count.saturating_add(1);
                }
            });
            count
        };

        let mut ranges: Vec<(usize, usize)> = Vec::new();
        if ranges.try_reserve_exact(user_area_count).is_err() {
            return Err(axerrno::LinuxError::ENOMEM);
        }
        {
            let aspace_handle = self.aspace_handle();
            let aspace = aspace_handle.read();
            aspace.for_each_area(|start, end, flags| {
                if !flags.contains(MappingFlags::USER) {
                    return;
                }
                let s = start.align_down_4k().as_usize();
                let e = end.align_up_4k().as_usize();
                if e > s {
                    ranges.push((s, e - s));
                }
            });
        }
        for (start, len) in ranges {
            self.lock_mapped_range(start, len)?;
        }
        Ok(())
    }

    pub fn maybe_lock_future_range(
        &self,
        addr: usize,
        len: usize,
    ) -> Result<(), axerrno::LinuxError> {
        if len == 0 || !self.memlock_future_enabled() {
            return Ok(());
        }
        self.lock_mapped_range(addr, len)
    }
}
