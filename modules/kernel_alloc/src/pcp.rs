//! Per-CPU Order-0 physical page frame hot cache pool (PCP).
//!
//! Provides bounded CPU-local caching for single 4K physical page allocations and frees,
//! avoiding contention on the global Buddy lock on SMP systems.

use kspin::SpinRaw;

/// Maximum number of Order-0 pages cached per CPU.
pub const PCP_CAPACITY: usize = 64;

/// Number of pages refilled or drained in a single batch with Buddy.
pub const PCP_BATCH_SIZE: usize = 16;

/// High watermark: when local cache reaches this count during single-page free,
/// a batch of `PCP_BATCH_SIZE` pages is drained to Buddy.
pub const PCP_HIGH_WATERMARK: usize = 48;

/// Fixed-capacity LIFO cache of Order-0 physical page addresses for a single CPU.
#[derive(Debug)]
pub struct Order0Pcp {
    pages: [usize; PCP_CAPACITY],
    count: usize,
}

impl Order0Pcp {
    /// Creates an empty Order-0 page cache.
    pub const fn new() -> Self {
        Self {
            pages: [0; PCP_CAPACITY],
            count: 0,
        }
    }

    /// Returns the number of cached pages.
    #[inline]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns whether the cache is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns whether the cache is full.
    #[inline]
    pub const fn is_full(&self) -> bool {
        self.count >= PCP_CAPACITY
    }

    /// Returns true if the cache has reached or exceeded the high watermark.
    #[inline]
    pub const fn needs_drain(&self) -> bool {
        self.count >= PCP_HIGH_WATERMARK
    }

    /// Pops one page from the cache if available.
    #[inline]
    pub fn pop(&mut self) -> Option<usize> {
        if self.count > 0 {
            self.count -= 1;
            Some(self.pages[self.count])
        } else {
            None
        }
    }

    /// Pops up to `out.len()` pages from the cache into `out`.
    /// Returns the number of pages actually popped.
    pub fn pop_batch(&mut self, out: &mut [usize]) -> usize {
        let n = out.len().min(self.count);
        for i in 0..n {
            self.count -= 1;
            out[i] = self.pages[self.count];
        }
        n
    }

    /// Pushes a single page into the cache. Returns false if full.
    #[inline]
    pub fn push(&mut self, page: usize) -> bool {
        if self.count < PCP_CAPACITY {
            self.pages[self.count] = page;
            self.count += 1;
            true
        } else {
            false
        }
    }

    /// Pushes multiple pages into the cache up to capacity.
    /// Returns the number of pages actually pushed.
    pub fn push_batch(&mut self, pages: &[usize]) -> usize {
        let space = PCP_CAPACITY - self.count;
        let to_push = space.min(pages.len());
        for &p in &pages[..to_push] {
            self.pages[self.count] = p;
            self.count += 1;
        }
        to_push
    }

    /// Drains all pages from the cache into `out`.
    /// Returns the number of drained pages.
    pub fn drain_all(&mut self, out: &mut [usize]) -> usize {
        self.pop_batch(out)
    }
}

impl Default for Order0Pcp {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-CPU wrapper holding an `Order0Pcp` guarded by a spinlock.
pub struct PerCpuPcp {
    inner: SpinRaw<Order0Pcp>,
}

// SAFETY: PerCpuPcp is accessed with local IRQs disabled for current CPU,
// and other CPUs acquire `inner.lock()` during cross-CPU drains.
unsafe impl Sync for PerCpuPcp {}

impl PerCpuPcp {
    /// Creates an uninitialized `PerCpuPcp`.
    pub const fn new_uninit() -> Self {
        Self {
            inner: SpinRaw::new(Order0Pcp::new()),
        }
    }

    /// Initializes this per-CPU cache during CPU bring-up.
    pub fn init_during_cpu_bringup(&mut self) {
        *self.inner.get_mut() = Order0Pcp::new();
    }

    /// Pops one page from this per-CPU cache.
    #[inline]
    pub fn pop(&self) -> Option<usize> {
        self.inner.lock().pop()
    }

    /// Pushes multiple pages into this per-CPU cache up to capacity.
    #[inline]
    pub fn push_batch(&self, pages: &[usize]) -> usize {
        self.inner.lock().push_batch(pages)
    }

    /// Drains all pages from this per-CPU cache into `out`.
    #[inline]
    pub fn drain_all(&self, out: &mut [usize]) -> usize {
        self.inner.lock().drain_all(out)
    }

    /// Returns the count of cached pages in this per-CPU cache.
    #[inline]
    pub fn count(&self) -> usize {
        self.inner.lock().count()
    }

    /// Pushes a page into the cache, draining a batch of `PCP_BATCH_SIZE` pages
    /// to `drain_buf` if the high watermark is reached.
    ///
    /// Returns:
    /// - `Ok(None)`: page pushed successfully without drain.
    /// - `Ok(Some(n))`: page pushed successfully, `n` pages were drained into `drain_buf`.
    /// - `Err(page)`: cache was full and push failed; caller must free `page` directly to Buddy.
    pub fn push_or_drain(&self, page: usize, drain_buf: &mut [usize]) -> Result<Option<usize>, usize> {
        let mut inner = self.inner.lock();
        if inner.push(page) {
            if inner.needs_drain() {
                let n = inner.pop_batch(drain_buf);
                Ok(Some(n))
            } else {
                Ok(None)
            }
        } else {
            // Cache was unexpectedly full: drain a batch to make room, then push
            let n = inner.pop_batch(drain_buf);
            if inner.push(page) {
                Ok(Some(n))
            } else {
                Err(page)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcp_push_pop_lifo() {
        let mut pcp = Order0Pcp::new();
        assert_eq!(pcp.count(), 0);
        assert!(pcp.is_empty());
        assert_eq!(pcp.pop(), None);

        assert!(pcp.push(0x1000));
        assert!(pcp.push(0x2000));
        assert_eq!(pcp.count(), 2);
        assert!(!pcp.is_empty());

        assert_eq!(pcp.pop(), Some(0x2000));
        assert_eq!(pcp.pop(), Some(0x1000));
        assert_eq!(pcp.pop(), None);
        assert_eq!(pcp.count(), 0);
    }

    #[test]
    fn test_pcp_capacity_limit() {
        let mut pcp = Order0Pcp::new();
        for i in 0..PCP_CAPACITY {
            assert!(pcp.push(0x1000 * (i + 1)), "push {} must succeed", i);
        }
        assert_eq!(pcp.count(), PCP_CAPACITY);
        assert!(pcp.is_full());
        assert!(!pcp.push(0x999000), "push when full must return false");
        assert_eq!(pcp.count(), PCP_CAPACITY);
    }

    #[test]
    fn test_pcp_batch_pop() {
        let mut pcp = Order0Pcp::new();
        for i in 0..32 {
            pcp.push(0x1000 * (i + 1));
        }
        assert_eq!(pcp.count(), 32);

        let mut buf = [0usize; PCP_BATCH_SIZE];
        let n = pcp.pop_batch(&mut buf);
        assert_eq!(n, PCP_BATCH_SIZE);
        assert_eq!(pcp.count(), 16);
        assert_eq!(buf[0], 0x1000 * 32);
        assert_eq!(buf[15], 0x1000 * 17);
    }

    #[test]
    fn test_pcp_watermarks_and_drain_all() {
        let mut pcp = Order0Pcp::new();
        for i in 0..PCP_HIGH_WATERMARK - 1 {
            pcp.push(0x1000 * (i + 1));
        }
        assert!(!pcp.needs_drain());

        pcp.push(0x1000 * PCP_HIGH_WATERMARK);
        assert!(pcp.needs_drain());

        let mut drain_buf = [0usize; PCP_CAPACITY];
        let drained = pcp.drain_all(&mut drain_buf);
        assert_eq!(drained, PCP_HIGH_WATERMARK);
        assert_eq!(pcp.count(), 0);
        assert!(pcp.is_empty());
    }

    #[test]
    fn test_pcp_push_batch() {
        let mut pcp = Order0Pcp::new();
        let pages = [0x1000, 0x2000, 0x3000, 0x4000];
        let pushed = pcp.push_batch(&pages);
        assert_eq!(pushed, 4);
        assert_eq!(pcp.count(), 4);
        assert_eq!(pcp.pop(), Some(0x4000));
    }

    #[test]
    fn test_percpu_push_or_drain() {
        let pcp = PerCpuPcp::new_uninit();
        let mut drain_buf = [0usize; PCP_BATCH_SIZE];

        for i in 0..PCP_HIGH_WATERMARK - 1 {
            let res = pcp.push_or_drain(0x1000 * (i + 1), &mut drain_buf);
            assert_eq!(res, Ok(None));
        }
        assert_eq!(pcp.count(), PCP_HIGH_WATERMARK - 1);

        let res = pcp.push_or_drain(0x1000 * PCP_HIGH_WATERMARK, &mut drain_buf);
        assert_eq!(res, Ok(Some(PCP_BATCH_SIZE)));
        assert_eq!(pcp.count(), PCP_HIGH_WATERMARK - PCP_BATCH_SIZE);
        assert_eq!(drain_buf[0], 0x1000 * PCP_HIGH_WATERMARK);
        assert_eq!(drain_buf[PCP_BATCH_SIZE - 1], 0x1000 * (PCP_HIGH_WATERMARK - PCP_BATCH_SIZE + 1));
    }
}

