//! User-defined task extended data.

use core::alloc::Layout;
use core::mem::{align_of, size_of};

#[unsafe(no_mangle)]
#[linkage = "weak"]
fn __ax_task_ext_name() -> *const u8 {
    core::ptr::null()
}

#[unsafe(no_mangle)]
#[linkage = "weak"]
fn __ax_task_ext_name_len() -> usize {
    0
}

/// A wrapper of pointer to the task extended data.
pub struct AxTaskExt {
    ptr: *mut u8,
}

impl AxTaskExt {
    /// Returns the expected type name of the task extended structure.
    pub fn ext_name() -> &'static str {
        unsafe extern "C" {
            fn __ax_task_ext_name() -> *const u8;
            fn __ax_task_ext_name_len() -> usize;
        }
        let ptr = unsafe { __ax_task_ext_name() };
        if ptr.is_null() {
            ""
        } else {
            let len = unsafe { __ax_task_ext_name_len() };
            let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
            core::str::from_utf8(slice).unwrap_or("")
        }
    }

    /// Returns the expected size of the task extended structure.
    pub fn size() -> usize {
        unsafe extern "C" {
            static __AX_TASK_EXT_SIZE: usize;
        }
        unsafe { __AX_TASK_EXT_SIZE }
    }

    /// Returns the expected alignment of the task extended structure.
    pub fn align() -> usize {
        unsafe extern "C" {
            static __AX_TASK_EXT_ALIGN: usize;
        }
        unsafe { __AX_TASK_EXT_ALIGN }
    }

    /// Construct an empty task extended structure that contains no data
    /// (zero size).
    pub const fn empty() -> Self {
        Self {
            ptr: core::ptr::null_mut(),
        }
    }

    /// Returns `true` if the task extended structure is empty.
    pub const fn is_empty(&self) -> bool {
        self.ptr.is_null()
    }

    /// Allocates the space for the task extended data, but does not
    /// initialize the data.
    pub unsafe fn uninited() -> Self {
        let size = Self::size();
        let align = Self::align();
        let ptr = if size == 0 {
            core::ptr::null_mut()
        } else {
            let layout = Layout::from_size_align(size, align).unwrap();
            unsafe { alloc::alloc::alloc(layout) }
        };
        Self { ptr }
    }

    /// Gets the raw pointer to the task extended data.
    pub const fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Invoke the task-enter hook for the extended data.
    pub fn on_enter(&self) {
        if !self.ptr.is_null() {
            unsafe extern "C" {
                fn __ax_task_ext_on_enter(data: *const u8);
            }
            unsafe { __ax_task_ext_on_enter(self.ptr.cast_const()) };
        }
    }

    /// Invoke the task-leave hook for the extended data.
    pub fn on_leave(&self) {
        if !self.ptr.is_null() {
            unsafe extern "C" {
                fn __ax_task_ext_on_leave(data: *const u8);
            }
            unsafe { __ax_task_ext_on_leave(self.ptr.cast_const()) };
        }
    }

    /// Write the given object to the task extended data.
    ///
    /// Returns [`None`] if the data size is zero, otherwise returns a mutable
    /// reference to the content.
    ///
    /// # Panics
    ///
    /// Panics If the sizes and alignments of the two object do not match.
    pub fn write<T: Sized>(&mut self, data: T) -> Option<&mut T> {
        let data_size = size_of::<T>();
        let data_align = align_of::<T>();
        if data_size != Self::size() {
            panic!("size mismatch: {} != {}", data_size, Self::size());
        }
        if data_align != Self::align() {
            panic!("align mismatch: {} != {}", data_align, Self::align());
        }

        if self.ptr.is_null() {
            *self = unsafe { Self::uninited() };
        }
        if data_size > 0 {
            let ptr = self.ptr as *mut T;
            assert!(!ptr.is_null());
            unsafe {
                ptr.write(data);
                Some(&mut *ptr)
            }
        } else {
            None
        }
    }
}

impl Drop for AxTaskExt {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe extern "C" {
                fn __ax_task_ext_drop(data: *mut u8);
            }
            unsafe { __ax_task_ext_drop(self.ptr) };

            let layout = Layout::from_size_align(Self::size(), Self::align()).unwrap();
            unsafe { alloc::alloc::dealloc(self.ptr, layout) };
        }
    }
}

/// A trait to convert [`TaskInner::task_ext_ptr`] to the reference of the
/// concrete type.
///
/// [`TaskInner::task_ext_ptr`]: crate::TaskInner::task_ext_ptr
pub trait TaskExtRef<T: Sized> {
    /// Get a reference to the task extended data.
    fn task_ext(&self) -> &T;
    fn task_ext_opt(&self) -> Option<&T>;
}

/// A trait to convert [`TaskInner::task_ext_ptr`] to the mutable reference of
/// the concrete type.
///
/// [`TaskInner::task_ext_ptr`]: crate::TaskInner::task_ext_ptr
pub trait TaskExtMut<T: Sized> {
    /// Get a mutable reference to the task extended data.
    fn task_ext_mut(&mut self) -> &mut T;
    fn task_ext_mut_opt(&mut self) -> Option<&mut T>;
}

/// Optional lifecycle hooks for task-extended data.
pub trait TaskExtSwitch {
    /// Called when the task is switched in on a CPU.
    fn on_enter(&self) {}

    /// Called when the task is switched out from a CPU.
    fn on_leave(&self) {}
}

/// Define the task extended data.
///
/// It automatically implements [`TaskExtRef`] and [`TaskExtMut`] for
/// [`TaskInner`].
///
/// # Example
///
/// ```
/// # #![allow(non_local_definitions)]
/// use axtask::{def_task_ext, TaskExtRef, TaskInner};
///
/// pub struct TaskExtImpl {
///    proc_id: usize,
/// }
///
/// def_task_ext!(TaskExtImpl);
///
/// axtask::init_scheduler();
///
/// let mut inner = TaskInner::new(|| {},  "".into(), 0x1000);
/// assert!(inner.init_task_ext(TaskExtImpl { proc_id: 233 }).is_some());
/// // cannot initialize twice
/// assert!(inner.init_task_ext(TaskExtImpl { proc_id: 0xdead }).is_none());
///
/// let task = axtask::spawn_task(inner);
/// assert_eq!(task.task_ext().proc_id, 233);
/// ```
///
/// [`TaskInner`]: crate::TaskInner
#[macro_export]
macro_rules! def_task_ext {
    ($task_ext_struct:ty) => {
        #[unsafe(no_mangle)]
        static __AX_TASK_EXT_SIZE: usize = ::core::mem::size_of::<$task_ext_struct>();

        #[unsafe(no_mangle)]
        static __AX_TASK_EXT_ALIGN: usize = ::core::mem::align_of::<$task_ext_struct>();

        #[unsafe(no_mangle)]
        fn __ax_task_ext_drop(data: *mut u8) {
            unsafe { core::ptr::drop_in_place(data as *mut $task_ext_struct) };
        }

        #[unsafe(no_mangle)]
        fn __ax_task_ext_on_enter(data: *const u8) {
            unsafe {
                <$task_ext_struct as $crate::TaskExtSwitch>::on_enter(
                    &*(data as *const $task_ext_struct),
                )
            };
        }

        #[unsafe(no_mangle)]
        fn __ax_task_ext_on_leave(data: *const u8) {
            unsafe {
                <$task_ext_struct as $crate::TaskExtSwitch>::on_leave(
                    &*(data as *const $task_ext_struct),
                )
            };
        }

        #[unsafe(no_mangle)]
        fn __ax_task_ext_name() -> *const u8 {
            ::core::any::type_name::<$task_ext_struct>().as_ptr()
        }

        #[unsafe(no_mangle)]
        fn __ax_task_ext_name_len() -> usize {
            ::core::any::type_name::<$task_ext_struct>().len()
        }

        impl $crate::TaskExtRef<$task_ext_struct> for $crate::TaskInner {
            fn task_ext(&self) -> &$task_ext_struct {
                self.task_ext_opt().expect("task extension not initialized")
            }

            fn task_ext_opt(&self) -> Option<&$task_ext_struct> {
                let ext_name = $crate::AxTaskExt::ext_name();
                let req_name = ::core::any::type_name::<$task_ext_struct>();
                if ext_name != req_name {
                    panic!(
                        "task extension type mismatch! Compiled extension: {}, but trying to access as: {}",
                        ext_name, req_name
                    );
                }
                unsafe {
                    let ptr = self.task_ext_ptr() as *const $task_ext_struct;
                    if ptr.is_null() {
                        None
                    } else {
                        Some(&*ptr)
                    }
                }
            }
        }

        impl $crate::TaskExtMut<$task_ext_struct> for $crate::TaskInner {
            fn task_ext_mut(&mut self) -> &mut $task_ext_struct {
                self.task_ext_mut_opt().expect("task extension not initialized")
            }

            fn task_ext_mut_opt(&mut self) -> Option<&mut $task_ext_struct> {
                let ext_name = $crate::AxTaskExt::ext_name();
                let req_name = ::core::any::type_name::<$task_ext_struct>();
                if ext_name != req_name {
                    panic!(
                        "task extension type mismatch! Compiled extension: {}, but trying to access as: {}",
                        ext_name, req_name
                    );
                }
                unsafe {
                    let ptr = self.task_ext_ptr() as *mut $task_ext_struct;
                    if ptr.is_null() {
                        None
                    } else {
                        Some(&mut *ptr)
                    }
                }
            }
        }
    };
}
