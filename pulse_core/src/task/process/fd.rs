use super::*;

impl Process {
    pub fn get_fd_entry(&self, fd: usize) -> Result<crate::fd_table::FdEntry, axerrno::LinuxError> {
        self.fd_table().read().get_entry_cloned(fd)
    }

    pub fn get_fd_object(
        &self,
        fd: usize,
    ) -> Result<alloc::sync::Arc<dyn crate::fd_table::FdObject>, axerrno::LinuxError> {
        self.fd_table().read().get_object(fd)
    }

    pub fn get_fd_objects(
        &self,
        fds: impl Iterator<Item = usize>,
    ) -> Result<
        alloc::vec::Vec<Option<alloc::sync::Arc<dyn crate::fd_table::FdObject>>>,
        axerrno::LinuxError,
    > {
        self.fd_table().read().objects_snapshot(fds)
    }

    pub fn insert_fd_entry(
        &self,
        entry: crate::fd_table::FdEntry,
    ) -> Result<usize, axerrno::LinuxError> {
        let limit = self.resources.lock().rlimit_state.nofile_soft as usize;
        let binding = self.fd_table();
        let mut table = binding.write();
        let fd = table.insert_next(entry)?;
        if fd >= limit {
            table.remove(fd);
            return Err(axerrno::LinuxError::EMFILE);
        }
        Ok(fd)
    }

    pub fn insert_fd_entry_from(
        &self,
        min_fd: usize,
        entry: crate::fd_table::FdEntry,
    ) -> Result<usize, axerrno::LinuxError> {
        let limit = self.resources.lock().rlimit_state.nofile_soft as usize;
        let binding = self.fd_table();
        let mut table = binding.write();
        let fd = table.insert_from(min_fd, entry)?;
        if fd >= limit {
            table.remove(fd);
            return Err(axerrno::LinuxError::EMFILE);
        }
        Ok(fd)
    }

    pub fn set_fd_entry(
        &self,
        fd: usize,
        entry: crate::fd_table::FdEntry,
    ) -> Result<(), axerrno::LinuxError> {
        let limit = self.resources.lock().rlimit_state.nofile_soft as usize;
        if fd >= limit {
            return Err(axerrno::LinuxError::EBADF);
        }
        let replaced = {
            let binding = self.fd_table();
            let mut table = binding.write();
            let replaced = table.get(fd).cloned();
            table.insert_at(fd, entry)?;
            replaced
        };
        if let Some(entry) = replaced {
            self.release_posix_locks_for_entry(&entry);
        }
        Ok(())
    }

    pub fn remove_fd_entry(
        &self,
        fd: usize,
    ) -> Result<crate::fd_table::FdEntry, axerrno::LinuxError> {
        let entry = self.fd_table().write().remove_or_err(fd)?;
        self.release_posix_locks_for_entry(&entry);
        Ok(entry)
    }

    fn release_posix_locks_for_entry(&self, entry: &crate::fd_table::FdEntry) {
        let target = crate::flock::get_lock_target(&entry.object);
        crate::record_lock::release_posix_owner_target(self.pid(), target);
    }

    pub(in crate::task) fn release_posix_locks_for_entries(
        &self,
        entries: &[crate::fd_table::FdEntry],
    ) {
        for entry in entries {
            self.release_posix_locks_for_entry(entry);
        }
    }

    pub fn set_fd_cloexec(&self, fd: usize, cloexec: bool) -> Result<(), axerrno::LinuxError> {
        let binding = self.fd_table();
        let mut table = binding.write();
        let entry = table.get_mut(fd).ok_or(axerrno::LinuxError::EBADF)?;
        entry.flags.set(crate::fd_table::FdFlags::CLOEXEC, cloexec);
        Ok(())
    }

    pub fn set_fd_nonblocking(
        &self,
        fd: usize,
        nonblocking: bool,
    ) -> Result<(), axerrno::LinuxError> {
        let object = {
            let binding = self.fd_table();
            let mut table = binding.write();
            let entry = table.get_mut(fd).ok_or(axerrno::LinuxError::EBADF)?;
            entry
                .flags
                .set(crate::fd_table::FdFlags::NONBLOCK, nonblocking);
            entry.object.clone()
        };
        object.set_nonblocking(nonblocking)?;
        Ok(())
    }

    pub fn get_fd_location(&self, fd: usize) -> Result<axfs_ng_vfs::Location, axerrno::LinuxError> {
        self.get_fd_object(fd)?
            .location()
            .ok_or(axerrno::LinuxError::EBADF)
    }

    pub fn fd_entries_snapshot(&self) -> alloc::vec::Vec<crate::fd_table::FdEntry> {
        self.fd_table().read().entries_snapshot()
    }
}
