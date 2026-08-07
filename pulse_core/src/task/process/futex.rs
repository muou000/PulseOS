use super::*;
use crate::task;

impl Process {
    fn futex_key(&self, addr: usize, is_private: bool) -> (usize, bool) {
        if is_private {
            (addr, true)
        } else {
            let _ =
                self.try_fault_in_user_range(addr, core::mem::size_of::<u32>(), MappingFlags::READ);
            let aspace_handle = self.aspace_handle();
            let aspace = aspace_handle.read();
            let vaddr = VirtAddr::from(addr);
            let paddr = aspace
                .query_vaddr(vaddr)
                .map(|(paddr, ..)| paddr.as_usize())
                .unwrap_or(addr);
            axlog::debug!("futex_key: addr={:#x}, paddr={:#x}", addr, paddr);
            (paddr, false)
        }
    }

    pub fn futex_waitv(
        &self,
        waiters_addr: usize,
        nr_futexes: u32,
        _flags: u32,
        timeout_ns: Option<u64>,
    ) -> AxResult<isize> {
        let mut waiters = alloc::vec::Vec::with_capacity(nr_futexes as usize);
        for i in 0..nr_futexes {
            let mut w = FutexWaitv::default();
            let buf = unsafe {
                core::slice::from_raw_parts_mut(
                    &mut w as *mut _ as *mut u8,
                    core::mem::size_of::<FutexWaitv>(),
                )
            };
            self.read_user_bytes(
                waiters_addr + i as usize * core::mem::size_of::<FutexWaitv>(),
                buf,
            )?;
            waiters.push(w);
        }

        for w in &waiters {
            if w.__reserved != 0 {
                return Err(AxError::InvalidInput);
            }
            let valid_flags = 0x02 | 0x80;
            if (w.flags & !valid_flags) != 0 || (w.flags & 0x03) != 0x02 {
                return Err(AxError::InvalidInput);
            }
            if w.uaddr % 4 != 0 {
                return Err(AxError::InvalidInput);
            }
            if w.uaddr == 0 {
                return Err(AxError::BadAddress);
            }
            self.try_fault_in_user_range(
                w.uaddr as usize,
                core::mem::size_of::<u32>(),
                MappingFlags::READ,
            )?;
            let val = self.read_user_u32(w.uaddr as usize)?;
            if val != w.val as u32 {
                return Err(AxError::from(AxErrorKind::WouldBlock));
            }
        }

        // Translate the virtual addresses to physical addresses outside the run queue lock.
        let mut kvaddrs = alloc::vec::Vec::with_capacity(waiters.len());
        let aspace = self.aspace_handle();
        let aspace_guard = aspace.read();
        for w in &waiters {
            let start = VirtAddr::from(w.uaddr as usize);
            let (paddr, ..) = aspace_guard
                .query_vaddr(start)
                .map_err(|_| AxError::BadAddress)?;
            let paddr = paddr.align_down_4k() + start.align_offset_4k();
            let kvaddr = axhal::mem::phys_to_virt(paddr);
            kvaddrs.push(kvaddr.as_usize());
        }
        drop(aspace_guard);

        let current_thread = task::current_thread().ok();
        let signal_pending = || {
            current_thread
                .as_ref()
                .map(|thread| thread.has_pending_signal())
                .unwrap_or(false)
        };

        if signal_pending() {
            return Err(unsafe { core::mem::transmute(-512i32) }); // ERESTARTSYS
        }

        let mut queues = alloc::vec::Vec::with_capacity(waiters.len());
        let mut queue_keys = alloc::vec::Vec::with_capacity(waiters.len());
        for w in &waiters {
            let is_priv = w.flags & 128 != 0; // 128 is FUTEX_PRIVATE_FLAG
            let (key, is_priv) = self.futex_key(w.uaddr as usize, is_priv);
            let queue = if is_priv {
                self.futex_table.queue(key)
            } else {
                GLOBAL_FUTEX_TABLE.queue(key)
            };
            queues.push(queue);
            queue_keys.push((key, is_priv));
        }

        let q_refs: alloc::vec::Vec<&axtask::WaitQueue> =
            queues.iter().map(|q| q.as_ref()).collect();

        let mut mismatch = false;

        let resource_id = queue_keys.first().map(|(key, _)| *key as u64).unwrap_or(0);
        let res = axtask::WaitQueue::wait_multiple_timeout_until_with_context(
            &q_refs,
            timeout_ns.map(core::time::Duration::from_nanos),
            WaitContext::new(|| (WaitReason::FutexWaitV, resource_id, nr_futexes as u64)),
            || {
                if self.group_exiting() || signal_pending() {
                    return true;
                }
                mismatch = false;
                for (i, w) in waiters.iter().enumerate() {
                    let kvaddr = kvaddrs[i];
                    let val = unsafe { core::ptr::read_volatile(kvaddr as *const u32) };
                    if val != w.val as u32 {
                        mismatch = true;
                        return true;
                    }
                }
                false
            },
        );

        drop(q_refs);
        drop(queues);
        for (key, is_priv) in queue_keys {
            if is_priv {
                self.futex_table.remove_if_empty(key);
            } else {
                GLOBAL_FUTEX_TABLE.remove_if_empty(key);
            }
        }

        if mismatch {
            return Err(AxError::from(AxErrorKind::WouldBlock)); // EAGAIN
        }

        if signal_pending() {
            return Err(unsafe { core::mem::transmute(-512i32) }); // ERESTARTSYS
        }

        match res {
            Ok(idx) => Ok(idx as isize),
            Err(true) => Err(AxError::from(AxErrorKind::TimedOut)),
            Err(false) => Err(unsafe { core::mem::transmute(-512i32) }), // Aborted not by timeout
        }
    }

    pub fn futex_wait(
        &self,
        addr: usize,
        expected: u32,
        timeout_ns: Option<u64>,
        is_private: bool,
    ) -> AxResult<()> {
        self.futex_wait_mask(addr, expected, timeout_ns, is_private, u32::MAX)
    }

    pub fn futex_wait_mask(
        &self,
        addr: usize,
        expected: u32,
        timeout_ns: Option<u64>,
        is_private: bool,
        bitset: u32,
    ) -> AxResult<()> {
        self.try_fault_in_user_range(addr, core::mem::size_of::<u32>(), MappingFlags::READ)?;
        let val = self.read_user_u32(addr)?;
        if val != expected {
            return Err(AxError::from(AxErrorKind::WouldBlock));
        }

        // Translate the virtual address to a physical address outside the run queue lock.
        let aspace = self.aspace_handle();
        let start = VirtAddr::from(addr);
        let (paddr, ..) = aspace
            .read()
            .query_vaddr(start)
            .map_err(|_| AxError::BadAddress)?;
        let paddr = paddr.align_down_4k() + start.align_offset_4k();
        let kvaddr = axhal::mem::phys_to_virt(paddr);

        let current_thread = task::current_thread().ok();
        let signal_pending = || {
            current_thread
                .as_ref()
                .map(|thread| thread.has_pending_signal())
                .unwrap_or(false)
        };
        if signal_pending() {
            return Err(unsafe { core::mem::transmute(-512i32) });
        }

        let (key, is_priv) = self.futex_key(addr, is_private);

        axlog::debug!(
            "futex_wait: tid={}, addr={:#x}, paddr={:#x}, expected={}, is_private={}",
            current_thread
                .as_ref()
                .map(|thread| thread.tid())
                .unwrap_or(0),
            addr,
            paddr.as_usize(),
            expected,
            is_private
        );

        let queue = if is_priv {
            self.futex_table.queue_mask(key, bitset)
        } else {
            GLOBAL_FUTEX_TABLE.queue_mask(key, bitset)
        };

        if self.group_exiting() {
            drop(queue);
            if is_priv {
                self.futex_table.remove_mask_if_empty(key, bitset);
            } else {
                GLOBAL_FUTEX_TABLE.remove_mask_if_empty(key, bitset);
            }
            return Ok(());
        }

        let first_time = core::cell::Cell::new(true);
        let mismatch = core::sync::atomic::AtomicBool::new(false);

        let timed_out = if let Some(timeout_ns) = timeout_ns {
            let dur = core::time::Duration::from_nanos(timeout_ns);
            queue.wait_timeout_until_with_context(
                WaitContext::new(|| (WaitReason::Futex, key as u64, expected as u64)),
                dur,
                || {
                    if first_time.get() {
                        first_time.set(false);
                        if self.group_exiting() || signal_pending() {
                            return true;
                        }
                        let val =
                            unsafe { core::ptr::read_volatile(kvaddr.as_usize() as *const u32) };
                        if val != expected {
                            mismatch.store(true, core::sync::atomic::Ordering::Relaxed);
                            return true;
                        }
                        false
                    } else {
                        true
                    }
                },
            )
        } else {
            queue.wait_until_with_context(
                WaitContext::new(|| (WaitReason::Futex, key as u64, expected as u64)),
                || {
                    if first_time.get() {
                        first_time.set(false);
                        if self.group_exiting() || signal_pending() {
                            return true;
                        }
                        let val =
                            unsafe { core::ptr::read_volatile(kvaddr.as_usize() as *const u32) };
                        if val != expected {
                            mismatch.store(true, core::sync::atomic::Ordering::Relaxed);
                            return true;
                        }
                        false
                    } else {
                        true
                    }
                },
            );
            false
        };

        drop(queue);
        if is_priv {
            self.futex_table.remove_mask_if_empty(key, bitset);
        } else {
            GLOBAL_FUTEX_TABLE.remove_mask_if_empty(key, bitset);
        }

        if self.group_exiting() {
            return Ok(());
        }
        if signal_pending() {
            return Err(unsafe { core::mem::transmute(-512i32) });
        }
        if mismatch.load(core::sync::atomic::Ordering::Relaxed) {
            return Err(AxError::from(AxErrorKind::WouldBlock));
        }
        if timed_out {
            return Err(AxError::from(AxErrorKind::TimedOut));
        }

        Ok(())
    }

    fn futex_wake_impl(
        &self,
        addr: usize,
        count: usize,
        resched: bool,
        is_private: bool,
        bitset: u32,
    ) -> usize {
        let (key, is_priv) = self.futex_key(addr, is_private);
        let woken = if is_priv {
            if resched {
                self.futex_table.wake_mask(key, count, bitset)
            } else {
                self.futex_table.wake_no_resched(key, count)
            }
        } else {
            if resched {
                GLOBAL_FUTEX_TABLE.wake_mask(key, count, bitset)
            } else {
                GLOBAL_FUTEX_TABLE.wake_no_resched(key, count)
            }
        };

        axlog::debug!(
            "futex_wake: tid={}, addr={:#x}, count={}, is_private={}, woken={}",
            current_thread().map(|thread| thread.tid()).unwrap_or(0),
            addr,
            count,
            is_private,
            woken
        );

        woken
    }

    pub fn futex_wake(&self, addr: usize, count: usize, is_private: bool) -> usize {
        self.futex_wake_impl(addr, count, true, is_private, u32::MAX)
    }

    pub fn futex_wake_mask(
        &self,
        addr: usize,
        count: usize,
        is_private: bool,
        bitset: u32,
    ) -> usize {
        self.futex_wake_impl(addr, count, true, is_private, bitset)
    }

    pub fn futex_wake_no_resched(&self, addr: usize, count: usize, is_private: bool) -> usize {
        self.futex_wake_impl(addr, count, false, is_private, u32::MAX)
    }

    pub fn futex_requeue(
        &self,
        addr: usize,
        wake_count: usize,
        target: usize,
        requeue_count: usize,
        is_private: bool,
    ) -> usize {
        let (key, is_priv) = self.futex_key(addr, is_private);
        let (target_key, _) = self.futex_key(target, is_private);
        let woken_requeued = if is_priv {
            self.futex_table
                .requeue(key, wake_count, target_key, requeue_count)
        } else {
            GLOBAL_FUTEX_TABLE.requeue(key, wake_count, target_key, requeue_count)
        };

        if is_priv {
            self.futex_table.remove_if_empty(key);
            self.futex_table.remove_if_empty(target_key);
        } else {
            GLOBAL_FUTEX_TABLE.remove_if_empty(key);
            GLOBAL_FUTEX_TABLE.remove_if_empty(target_key);
        }
        woken_requeued
    }

    pub fn exit_robust_list(&self, head_addr: usize) -> AxResult<()> {
        if head_addr == 0 {
            return Ok(());
        }

        let list_next = self.read_user_usize(head_addr)?;
        let futex_offset = self.read_user_isize(head_addr + core::mem::size_of::<usize>())?;
        let pending = self.read_user_usize(head_addr + core::mem::size_of::<usize>() * 2)?;
        let mut entry = list_next;
        let mut limit = ROBUST_LIST_LIMIT;

        while entry != 0 && entry != head_addr {
            let next = self.read_user_usize(entry)?;
            if entry != pending {
                self.wake_robust_entry(entry, futex_offset);
            }
            entry = next;
            limit -= 1;
            if limit == 0 {
                return Err(AxError::InvalidData);
            }
        }

        if pending != 0 {
            self.wake_robust_entry(pending, futex_offset);
        }
        Ok(())
    }

    fn wake_robust_entry(&self, entry: usize, futex_offset: isize) {
        let futex_addr = if futex_offset >= 0 {
            entry.wrapping_add(futex_offset as usize)
        } else {
            entry.wrapping_sub(futex_offset.unsigned_abs())
        };
        let _ = self.futex_wake_no_resched(futex_addr, 1, true);
        let _ = self.futex_wake_no_resched(futex_addr, 1, false);
    }
}
