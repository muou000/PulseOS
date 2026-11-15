//! Target-page classification checks with host-observed VirtIO storage reads.
//!
//! Deployment contract: run.py injects a two-page, non-sparse `fault-data`
//! file. Each byte of page n is 0x41+n. Only this process maps or modifies it.
//! The host acknowledges boundaries only after saving the device-trace cursor.
use super::*;

fn boundary(kind: &str, point: &str, address: usize) {
    say!("FAULT_CLASS kind={} point={} address={} pid={} tid={} time_ns={}",
        kind, point, address, ok("fault pid", syscall(172,0,0,0,0,0,0)),
        ok("fault tid", syscall(178,0,0,0,0,0,0)), monotonic_ns());
    // read's writable buffer is a live, initialized stack byte retained across
    // the synchronous syscall. No reference escapes to the kernel.
    let mut byte = [0u8; 1];
    loop {
        check!(syscall(63,0,byte.as_mut_ptr() as usize,1,0,0,0)==1,"fault boundary acknowledgment");
        if byte[0] == b'\n' { break; }
        check!(byte[0] == b'g',"unexpected fault boundary input");
    }
}

fn map(fd: usize, pages: usize, anonymous: bool) -> usize {
    let address = ok("classification mmap", syscall(222,0,pages*PAGE,3,
        if anonymous {0x22} else {2},fd,0));
    check!(address != 0 && address % PAGE == 0 && address.checked_add(pages*PAGE).is_some(),
        "classification mapping extent");
    address
}

fn unmap(address: usize, pages: usize) {
    check!(syscall(215,address,pages*PAGE,0,0,0,0)==0,"classification munmap");
}

fn touch(kind: &str, address: usize, expected: u8, write: bool,
         rings: &mut [Ring; CPUS], stats: &mut Stats) {
    boundary(kind,"begin",address);
    // SAFETY: all callers below pass the nonnull start of their successfully
    // mapped read/write page. The private mapping is live and exclusively used
    // by this thread until after this function returns. For file mappings the
    // injected file covers both pages and is not truncated. No Rust reference
    // is created from the pointer; u8 alignment is one and all values valid.
    // The write case uses MAP_PRIVATE, so its store cannot modify the backing
    // file or another mapping. Accesses precede every unmap; these volatile
    // operations retain the actual first-touch load/store used as evidence.
    unsafe {
        if write { core::ptr::write_volatile(address as *mut u8,expected); }
        check!(core::ptr::read_volatile(address as *const u8)==expected,
            "classification mapped data mismatch");
    }
    boundary(kind,"end",address);
    sleep_ms(2);
    drain_all(rings,stats);
}

pub fn run(rings: &mut [Ring; CPUS], stats: &mut Stats) {
    let anon=map(usize::MAX,1,true);
    touch("anonymous",anon,0,false,rings,stats);
    // Keep it live so later file targets cannot alias the anonymous address.
    let fd=ok("classification open",syscall(56,(-100isize) as usize,
        c"fault-data".as_ptr() as usize,0,0,0,0));
    let cold=map(fd,1,false);
    touch("cold",cold,0x41,false,rings,stats);
    let hot=map(fd,1,false);
    touch("hot",hot,0x41,false,rings,stats);
    touch("cow",cold,0x5a,true,rings,stats);
    // Verifies that the private COW store left the shared cache page intact.
    // SAFETY: hot remains a live readable mapping of one full data page and is
    // only accessed by this thread; its u8 load has no alignment/value hazard.
    check!(unsafe {core::ptr::read_volatile(hot as *const u8)}==0x41,
        "private file COW changed shared content");
    let batch=map(fd,2,false);
    // Page 0 is cached, page 1 has never been requested. The resolver may
    // return a shortened optional batch; page 1's I/O belongs to its own fault.
    touch("cached_target_cold_neighbor",batch,0x41,false,rings,stats);
    touch("cold_neighbor",batch+PAGE,0x42,false,rings,stats);
    unmap(batch,2);unmap(hot,1);unmap(cold,1);unmap(anon,1);close(fd);
    say!("FAULT_CLASS COMPLETE cases=6");
}
