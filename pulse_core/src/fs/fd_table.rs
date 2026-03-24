use alloc::sync::Arc;
use alloc::vec::Vec;
use axfs::api::File;
use spin::Mutex;

pub enum FileDesc {
    Stdin,
    Stdout,
    Stderr,
    File(Arc<Mutex<File>>),
}

pub struct FdTable {
    fds: Vec<Option<FileDesc>>,
}

impl FdTable {
    pub fn new() -> Self {
        let mut fds = Vec::new();
        fds.push(Some(FileDesc::Stdin)); // fd 0: stdin
        fds.push(Some(FileDesc::Stdout)); // fd 1: stdout
        fds.push(Some(FileDesc::Stderr)); // fd 2: stderr

        Self { fds }
    }

    pub fn alloc_fd(&mut self, file_desc: FileDesc) -> Option<usize> {
        for (i, slot) in self.fds.iter_mut().enumerate() {
            if i >= 3 && slot.is_none() {
                *slot = Some(file_desc);
                return Some(i);
            }
        }

        let fd = self.fds.len();
        self.fds.push(Some(file_desc));
        Some(fd)
    }

    pub fn get(&self, fd: usize) -> Option<&FileDesc> {
        self.fds.get(fd).and_then(|opt| opt.as_ref())
    }

    pub fn close(&mut self, fd: usize) -> bool {
        if fd < 3 {
            return false;
        }

        if let Some(slot) = self.fds.get_mut(fd) {
            if slot.is_some() {
                *slot = None;
                return true;
            }
        }
        false
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}
