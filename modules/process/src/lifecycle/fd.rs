use super::*;

impl Process {
    pub fn get_fd_entry(&self, fd: usize) -> Result<crate::fd::FdEntry, axerrno::LinuxError> {
        self.fd_table().read().get_entry_cloned(fd)
    }

    pub fn get_fd_object(
        &self,
        fd: usize,
    ) -> Result<alloc::sync::Arc<dyn crate::fd::FdObject>, axerrno::LinuxError> {
        self.fd_table().read().get_object(fd)
    }

    pub fn get_fd_objects(
        &self,
        fds: impl Iterator<Item = usize>,
    ) -> Result<
        alloc::vec::Vec<Option<alloc::sync::Arc<dyn crate::fd::FdObject>>>,
        axerrno::LinuxError,
    > {
        self.fd_table().read().objects_snapshot(fds)
    }

    pub fn check_next_fd_limit(&self) -> Result<usize, axerrno::LinuxError> {
        let limit = self.resources.lock().rlimit_state.nofile_soft as usize;
        let binding = self.fd_table();
        let table = binding.read();
        let next_fd = table.next_available_fd(0)?;
        if next_fd >= limit {
            return Err(axerrno::LinuxError::EMFILE);
        }
        Ok(next_fd)
    }

    pub fn insert_fd_entry(
        &self,
        entry: crate::fd::FdEntry,
    ) -> Result<usize, axerrno::LinuxError> {
        self.insert_fd_entry_into(&self.fd_table(), entry)
    }

    pub(crate) fn insert_fd_entry_into(
        &self,
        files: &SharedFdTable,
        entry: crate::fd::FdEntry,
    ) -> Result<usize, axerrno::LinuxError> {
        let limit = self.resources.lock().rlimit_state.nofile_soft as usize;
        let mut table = files.write();
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
        entry: crate::fd::FdEntry,
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
        entry: crate::fd::FdEntry,
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
    ) -> Result<crate::fd::FdEntry, axerrno::LinuxError> {
        let entry = self.fd_table().write().remove_or_err(fd)?;
        self.release_posix_locks_for_entry(&entry);
        Ok(entry)
    }

    pub fn close_fd_range(
        &self,
        first: usize,
        last: usize,
    ) -> alloc::vec::Vec<crate::fd::FdEntry> {
        let entries = self.fd_table().write().remove_range(first, last);
        self.release_posix_locks_for_entries(&entries);
        entries
    }

    fn release_posix_locks_for_entry(&self, entry: &crate::fd::FdEntry) {
        let target = crate::fd::flock::get_lock_target(&entry.object);
        crate::fd::record_lock::release_posix_owner_target(self.pid(), target);
    }

    pub(crate) fn release_posix_locks_for_entries(
        &self,
        entries: &[crate::fd::FdEntry],
    ) {
        for entry in entries {
            self.release_posix_locks_for_entry(entry);
        }
    }

    pub fn set_fd_cloexec(&self, fd: usize, cloexec: bool) -> Result<(), axerrno::LinuxError> {
        let binding = self.fd_table();
        let mut table = binding.write();
        let entry = table.get_mut(fd).ok_or(axerrno::LinuxError::EBADF)?;
        entry.flags.set(crate::fd::FdFlags::CLOEXEC, cloexec);
        Ok(())
    }

    pub fn set_fd_cloexec_range(&self, first: usize, last: usize) {
        self.fd_table().write().set_cloexec_range(first, last);
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
                .set(crate::fd::FdFlags::NONBLOCK, nonblocking);
            entry.object.clone()
        };
        object.set_nonblocking(nonblocking)?;
        Ok(())
    }

    pub fn get_fd_location(&self, fd: usize) -> Result<vfs::Location, axerrno::LinuxError> {
        self.get_fd_object(fd)?
            .location()
            .ok_or(axerrno::LinuxError::EBADF)
    }

    pub fn fd_entries_snapshot(&self) -> alloc::vec::Vec<crate::fd::FdEntry> {
        self.fd_table().read().entries_snapshot()
    }
}
