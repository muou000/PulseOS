use alloc::collections::BTreeMap;
#[allow(unused_imports)] // this is a weird false alarm
use alloc::vec::Vec;
use core::fmt;

use memory_addr::{AddrRange, MemoryAddr};

use crate::{MappingBackend, MappingError, MappingResult, MemoryArea};

/// A container that maintains memory mappings ([`MemoryArea`]).
pub struct MemorySet<B: MappingBackend> {
    areas: BTreeMap<B::Addr, MemoryArea<B>>,
}

impl<B: MappingBackend> MemorySet<B> {
    /// Creates a new memory set.
    pub const fn new() -> Self {
        Self {
            areas: BTreeMap::new(),
        }
    }

    /// Returns the number of memory areas in the memory set.
    pub fn len(&self) -> usize {
        self.areas.len()
    }

    /// Returns `true` if the memory set contains no memory areas.
    pub fn is_empty(&self) -> bool {
        self.areas.is_empty()
    }

    /// Returns the iterator over all memory areas.
    pub fn iter(&self) -> impl Iterator<Item = &MemoryArea<B>> {
        self.areas.values()
    }

    /// Returns whether the given address range overlaps with any existing area.
    pub fn overlaps(&self, range: AddrRange<B::Addr>) -> bool {
        if let Some((_, before)) = self.areas.range(..range.start).last() {
            if before.va_range().overlaps(range) {
                return true;
            }
        }
        if let Some((_, after)) = self.areas.range(range.start..).next() {
            if after.va_range().overlaps(range) {
                return true;
            }
        }
        false
    }

    /// Finds the memory area that contains the given address.
    pub fn find(&self, addr: B::Addr) -> Option<&MemoryArea<B>> {
        let candidate = self.areas.range(..=addr).last().map(|(_, a)| a);
        candidate.filter(|a| a.va_range().contains(addr))
    }

    /// Returns a mutable reference to the memory area starting at the given address.
    pub fn get_area_mut(&mut self, start: B::Addr) -> Option<&mut MemoryArea<B>> {
        self.areas.get_mut(&start)
    }

    /// Removes and returns the memory area starting at the given address, without modifying the page table.
    pub fn remove(&mut self, start: B::Addr) -> Option<MemoryArea<B>> {
        self.areas.remove(&start)
    }

    /// Inserts a memory area directly, without modifying the page table.
    pub fn insert(&mut self, start: B::Addr, area: MemoryArea<B>) {
        assert!(self.areas.insert(start, area).is_none());
    }

    /// Finds a free area that can accommodate the given size.
    ///
    /// The search starts from the given `hint` address, and the area should be
    /// within the given `limit` range.
    ///
    /// # Notes
    /// The `align` parameter specifies the alignment of the start address and
    /// the size of the area. The start address of the resulting area will
    /// be aligned to this value. Also, the size of the area must be a multiple
    /// of this value.
    ///
    /// # Returns
    /// Returns the start address of the free area. Returns `None` if no such
    /// area is found.
    pub fn find_free_area(
        &self,
        hint: B::Addr,
        size: usize,
        limit: AddrRange<B::Addr>,
        align: usize,
    ) -> Option<B::Addr> {
        if size % align != 0 {
            // size must be a multiple of align.
            return None;
        }
        // brute force: try each area's end address as the start.
        let mut last_end: <B as MappingBackend>::Addr = hint.max(limit.start).align_up(align);
        if let Some((_, area)) = self.areas.range(..last_end).last() {
            last_end = last_end.max(area.end()).align_up(align);
        }
        for (&addr, area) in self.areas.range(last_end..) {
            if last_end.checked_add(size).is_some_and(|end| end <= addr) {
                return Some(last_end);
            }
            last_end = area.end().align_up(align);
        }
        if last_end
            .checked_add(size)
            .is_some_and(|end| end <= limit.end)
        {
            Some(last_end)
        } else {
            None
        }
    }

    /// Add a new memory mapping.
    ///
    /// The mapping is represented by a [`MemoryArea`].
    ///
    /// If the new area overlaps with any existing area, the behavior is
    /// determined by the `unmap_overlap` parameter. If it is `true`, the
    /// overlapped regions will be unmapped first. Otherwise, it returns an
    /// error.
    pub fn map(
        &mut self,
        area: MemoryArea<B>,
        page_table: &mut B::PageTable,
        unmap_overlap: bool,
        reclaim: &mut B::Reclaim,
    ) -> MappingResult {
        if area.va_range().is_empty() {
            return Err(MappingError::InvalidParam);
        }

        if self.overlaps(area.va_range()) {
            if unmap_overlap {
                self.unmap(area.start(), area.size(), page_table, reclaim)?;
            } else {
                return Err(MappingError::AlreadyExists);
            }
        }

        area.map_area(page_table)?;
        assert!(self.areas.insert(area.start(), area).is_none());
        Ok(())
    }

    /// Remove memory mappings within the given address range.
    ///
    /// All memory areas that are fully contained in the range will be removed
    /// directly. If the area intersects with the boundary, it will be shrinked.
    /// If the unmapped range is in the middle of an existing area, it will be
    /// split into two areas.
    pub fn unmap(
        &mut self,
        start: B::Addr,
        size: usize,
        page_table: &mut B::PageTable,
        reclaim: &mut B::Reclaim,
    ) -> MappingResult {
        let range =
            AddrRange::try_from_start_size(start, size).ok_or(MappingError::InvalidParam)?;
        if range.is_empty() {
            return Ok(());
        }

        let end = range.end;

        // Unmap entire areas that are contained by the range.
        let mut unmap_error = None;
        self.areas.retain(|_, area| {
            if area.va_range().contained_in(range) {
                match area.unmap_area(page_table, reclaim) {
                    Ok(()) => false,
                    Err(error) => {
                        unmap_error.get_or_insert(error);
                        true
                    }
                }
            } else {
                true
            }
        });
        if let Some(error) = unmap_error {
            return Err(error);
        }

        // Shrink right if the area intersects with the left boundary.
        if let Some((&before_start, before)) = self.areas.range_mut(..start).last() {
            let before_end = before.end();
            if before_end > start {
                if before_end <= end {
                    // the unmapped area is at the end of `before`.
                    before.shrink_right(start.sub_addr(before_start), page_table, reclaim)?;
                } else {
                    // the unmapped area is in the middle `before`, need to split.
                    let middle_part = MemoryArea::new(
                        start,
                        end.sub_addr(start),
                        before.flags(),
                        before.backend().clone(),
                    );
                    middle_part.unmap_area(page_table, reclaim)?;
                    let right_part = before.split(end).unwrap();
                    before.set_end(start);
                    assert_eq!(right_part.start().into(), Into::<usize>::into(end));
                    self.areas.insert(end, right_part);
                }
            }
        }

        // Shrink left if the area intersects with the right boundary.
        if let Some((&after_start, after)) = self.areas.range_mut(start..).next() {
            let after_end = after.end();
            if after_start < end {
                // the unmapped area is at the start of `after`.
                let prefix = MemoryArea::new(
                    after_start,
                    end.sub_addr(after_start),
                    after.flags(),
                    after.backend().clone(),
                );
                prefix.unmap_area(page_table, reclaim)?;
                let right_part = after.split(end).unwrap();
                self.areas.remove(&after_start).unwrap();
                assert_eq!(right_part.end().into(), Into::<usize>::into(after_end));
                self.areas.insert(end, right_part);
            }
        }

        Ok(())
    }

    /// Remove all memory areas and the underlying mappings.
    pub fn clear(
        &mut self,
        page_table: &mut B::PageTable,
        reclaim: &mut B::Reclaim,
    ) -> MappingResult {
        let mut unmap_error = None;
        for (_, area) in self.areas.iter() {
            if let Err(error) = area.unmap_area(page_table, reclaim) {
                unmap_error.get_or_insert(error);
            }
        }
        self.areas.clear();
        unmap_error.map_or(Ok(()), Err)
    }

    /// Change the flags of memory mappings within the given address range.
    ///
    /// `update_flags` is a function that receives old flags and processes
    /// new flags (e.g., some flags can not be changed through this interface).
    /// It returns [`None`] if there is no bit to change.
    ///
    /// Memory areas will be skipped according to `update_flags`. Memory areas
    /// that are fully contained in the range or contains the range or
    /// intersects with the boundary will be handled similarly to `munmap`.
    pub fn protect(
        &mut self,
        start: B::Addr,
        size: usize,
        update_flags: impl Fn(B::Flags) -> Option<B::Flags>,
        page_table: &mut B::PageTable,
    ) -> MappingResult {
        let end = start.checked_add(size).ok_or(MappingError::InvalidParam)?;
        let mut to_insert = Vec::new();
        let mut protect_error = None;
        for (&area_start, area) in self.areas.iter_mut() {
            let area_end = area.end();

            if area_start >= end {
                // [ prot ]
                //          [ area ]
                break;
            }
            if area_end <= start {
                //          [ prot ]
                // [ area ]
                continue;
            }
            let Some(new_flags) = update_flags(area.flags()) else {
                continue;
            };

            let area_result = (|| -> MappingResult {
                if area_start >= start && area_end <= end {
                    // [   prot   ]
                    //   [ area ]
                    area.protect_area(new_flags, page_table)?;
                    area.set_flags(new_flags);
                } else if area_start < start && area_end > end {
                    //        [ prot ]
                    // [ left | area | right ]
                    let mut middle_part =
                        MemoryArea::new(start, size, area.flags(), area.backend().clone());
                    middle_part.protect_area(new_flags, page_table)?;
                    middle_part.set_flags(new_flags);

                    let right_part = area.split(end).unwrap();
                    area.set_end(start);
                    to_insert.push((right_part.start(), right_part));
                    to_insert.push((middle_part.start(), middle_part));
                } else if area_end > end {
                    // [    prot ]
                    //   [  area | right ]
                    let mut protected_part = MemoryArea::new(
                        area_start,
                        end.sub_addr(area_start),
                        area.flags(),
                        area.backend().clone(),
                    );
                    protected_part.protect_area(new_flags, page_table)?;
                    let right_part = area.split(end).unwrap();
                    area.set_flags(new_flags);

                    to_insert.push((right_part.start(), right_part));
                } else {
                    //        [ prot    ]
                    // [ left |  area ]
                    let mut protected_part = MemoryArea::new(
                        start,
                        area_end.sub_addr(start),
                        area.flags(),
                        area.backend().clone(),
                    );
                    protected_part.protect_area(new_flags, page_table)?;
                    let mut right_part = area.split(start).unwrap();
                    right_part.set_flags(new_flags);

                    to_insert.push((right_part.start(), right_part));
                }
                Ok(())
            })();
            if let Err(error) = area_result {
                protect_error = Some(error);
                break;
            }
        }
        self.areas.extend(to_insert);
        protect_error.map_or(Ok(()), Err)
    }
}

impl<B: MappingBackend> Default for MemorySet<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: MappingBackend> fmt::Debug for MemorySet<B>
where
    B::Addr: fmt::Debug,
    B::Flags: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.areas.values()).finish()
    }
}
