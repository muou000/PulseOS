#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

use axerrno::{AxError, AxResult, LinuxError};

mod sealed {
    pub trait Sealed {}
    impl<const N: usize> Sealed for [u8; N] {}
}

/// Sealed fixed-size initialized byte buffer `[u8; N]`.
///
/// Sealing guarantees in safe Rust that `zeroed()` initializes every byte to
/// `0u8` and that `as_ref().len() == Self::LEN` and `as_mut().len() == Self::LEN`.
pub trait AbiByteBuffer: sealed::Sealed + Copy + AsRef<[u8]> + AsMut<[u8]> {
    const LEN: usize;
    fn zeroed() -> Self;
}

impl<const N: usize> AbiByteBuffer for [u8; N] {
    const LEN: usize = N;

    #[inline]
    fn zeroed() -> Self {
        [0u8; N]
    }
}

/// Declares the exact Linux guest ABI representation size for a type via a
/// sealed `[u8; N]` byte buffer.
pub trait UserAbiType {
    type Buffer: AbiByteBuffer;
}

/// Returns the Linux ABI byte size of `T`.
#[inline]
pub const fn abi_size_of<T: UserAbiType>() -> usize {
    <T::Buffer as AbiByteBuffer>::LEN
}

/// Failure when decoding a value from user ABI bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiDecodeError {
    /// Input byte slice length did not match the expected ABI byte count.
    UnexpectedLength { expected: usize, actual: usize },
    /// User bytes did not form a valid representation for the target Rust type.
    InvalidRepresentation,
}

impl From<AbiDecodeError> for AxError {
    #[inline]
    fn from(_: AbiDecodeError) -> Self {
        AxError::InvalidInput
    }
}

impl From<AbiDecodeError> for LinuxError {
    #[inline]
    fn from(_: AbiDecodeError) -> Self {
        LinuxError::EINVAL
    }
}

/// Sequential / offset-aware reader over initialized user ABI bytes.
pub struct AbiReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> AbiReader<'a> {
    #[inline]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[inline]
    pub const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    #[inline]
    pub fn take_exact(&mut self, len: usize) -> Result<&'a [u8], AbiDecodeError> {
        let Some(end) = self.pos.checked_add(len) else {
            return Err(AbiDecodeError::UnexpectedLength {
                expected: len,
                actual: self.remaining(),
            });
        };
        let Some(slice) = self.bytes.get(self.pos..end) else {
            return Err(AbiDecodeError::UnexpectedLength {
                expected: len,
                actual: self.remaining(),
            });
        };
        self.pos = end;
        Ok(slice)
    }

    #[inline]
    pub fn read<T: FromUserAbi>(&mut self) -> Result<T, AbiDecodeError> {
        let raw = self.take_exact(abi_size_of::<T>())?;
        decode_from_bytes(raw)
    }
}

/// Sequential / offset-aware writer over a zero-initialized ABI byte slice.
pub struct AbiWriter<'a> {
    bytes: &'a mut [u8],
    pos: usize,
}

impl<'a> AbiWriter<'a> {
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> Self {
        bytes.fill(0);
        Self { bytes, pos: 0 }
    }

    #[inline]
    pub const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    #[inline]
    pub fn take_exact_mut(&mut self, len: usize) -> &mut [u8] {
        let end = self
            .pos
            .checked_add(len)
            .expect("AbiWriter::take_exact_mut overflowed target ABI buffer");
        assert!(
            end <= self.bytes.len(),
            "AbiWriter::take_exact_mut exceeded target ABI buffer"
        );
        let out = &mut self.bytes[self.pos..end];
        self.pos = end;
        out
    }

    #[inline]
    pub fn write<T: IntoUserAbi>(&mut self, value: &T) {
        let dst = self.take_exact_mut(abi_size_of::<T>());
        encode_into_slice(value, dst);
    }
}

/// Decodes a value of type `Self` from user ABI bytes while rejecting invalid
/// Rust value representations.
///
/// Reference-bearing types, function pointers, and unvalidated `Copy` enums do
/// not implement `FromUserAbi`:
///
/// ```compile_fail
/// use pulse_user_abi::decode_from_bytes;
/// let _ = decode_from_bytes::<&'static u8>(&[0u8; core::mem::size_of::<usize>()]);
/// ```
///
/// ```compile_fail
/// use pulse_user_abi::decode_from_bytes;
/// let _ = decode_from_bytes::<extern "C" fn()>(&[0u8; core::mem::size_of::<usize>()]);
/// ```
///
/// ```compile_fail
/// use pulse_user_abi::decode_from_bytes;
/// #[repr(u8)]
/// #[derive(Clone, Copy)]
/// enum Unvalidated { A = 0, B = 1 }
/// let _ = decode_from_bytes::<Unvalidated>(&[2u8]);
/// ```
pub trait FromUserAbi: UserAbiType + Sized {
    fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError>;
}

/// Encodes `Self` field-wise into initialized ABI bytes without reading
/// uninitialized Rust struct padding.
pub trait IntoUserAbi: UserAbiType {
    fn encode_abi(&self, writer: &mut AbiWriter<'_>);
}

/// Decodes `T` from an exact-length ABI byte slice.
pub fn decode_from_bytes<T: FromUserAbi>(bytes: &[u8]) -> Result<T, AbiDecodeError> {
    let expected = abi_size_of::<T>();
    if bytes.len() != expected {
        return Err(AbiDecodeError::UnexpectedLength {
            expected,
            actual: bytes.len(),
        });
    }
    let mut reader = AbiReader::new(bytes);
    let value = T::decode_abi(&mut reader)?;
    if reader.remaining() != 0 {
        return Err(AbiDecodeError::UnexpectedLength {
            expected,
            actual: expected.saturating_sub(reader.remaining()),
        });
    }
    Ok(value)
}

/// Encodes `value` into an exact-length mutable ABI byte slice, zeroing any
/// unwritten padding bytes first.
pub fn encode_into_slice<T: IntoUserAbi>(value: &T, dst: &mut [u8]) {
    let expected = abi_size_of::<T>();
    assert_eq!(
        dst.len(),
        expected,
        "encode_into_slice destination length mismatch"
    );
    let mut writer = AbiWriter::new(dst);
    value.encode_abi(&mut writer);
    assert_eq!(
        writer.remaining(),
        0,
        "IntoUserAbi::encode_abi did not consume exact ABI size"
    );
}

/// Encodes `value` into its fixed-size zero-padded ABI byte array `T::Buffer`.
pub fn encode_to_buffer<T: IntoUserAbi>(value: &T) -> T::Buffer {
    let mut buf = <T::Buffer as AbiByteBuffer>::zeroed();
    encode_into_slice(value, buf.as_mut());
    buf
}

/// Half-open canonical user virtual address range `[base, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserMemoryRange {
    pub base: usize,
    pub end: usize,
}

impl UserMemoryRange {
    #[inline]
    pub const fn new(base: usize, size: usize) -> Option<Self> {
        let Some(end) = base.checked_add(size) else {
            return None;
        };
        Some(Self { base, end })
    }

    #[inline]
    pub const fn contains(self, user_addr: usize, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let Some(user_end) = user_addr.checked_add(len) else {
            return false;
        };
        user_addr >= self.base && user_end <= self.end
    }

    #[inline]
    pub const fn validate(self, user_addr: usize, len: usize) -> AxResult<()> {
        if self.contains(user_addr, len) {
            Ok(())
        } else {
            Err(AxError::BadAddress)
        }
    }
}

/// Computes `count * abi_size_of::<T>()` while rejecting signed-count overflow
/// and arithmetic overflow with `AxError::InvalidInput` (`EINVAL`).
#[inline]
pub const fn checked_abi_array_size<T: UserAbiType>(count: usize) -> AxResult<usize> {
    if count > isize::MAX as usize {
        return Err(AxError::InvalidInput);
    }
    let Some(total_bytes) = count.checked_mul(abi_size_of::<T>()) else {
        return Err(AxError::InvalidInput);
    };
    if total_bytes > isize::MAX as usize {
        return Err(AxError::InvalidInput);
    }
    Ok(total_bytes)
}

/// Reads and validates a single `T` from `user_addr` using a partial byte-copy
/// transport. Short copies return `AxError::BadAddress` (`EFAULT`) before
/// representation decoding (`EINVAL`).
pub fn read_user_value_with<T: FromUserAbi>(
    user_addr: usize,
    mut read_partial: impl FnMut(usize, &mut [u8]) -> AxResult<usize>,
) -> AxResult<T> {
    let mut buf = <T::Buffer as AbiByteBuffer>::zeroed();
    let bytes = buf.as_mut();
    if !bytes.is_empty() {
        let copied = read_partial(user_addr, bytes)?;
        if copied != bytes.len() {
            return Err(AxError::BadAddress);
        }
    }
    decode_from_bytes::<T>(bytes).map_err(AxError::from)
}

/// Encodes `value` into zero-padded ABI bytes and writes as many bytes as the
/// transport accepts, returning the number of ABI bytes written.
pub fn write_user_value_partial_with<T: IntoUserAbi>(
    user_addr: usize,
    value: &T,
    mut write_partial: impl FnMut(usize, &[u8]) -> AxResult<usize>,
) -> AxResult<usize> {
    let buf = encode_to_buffer(value);
    let bytes = buf.as_ref();
    if bytes.is_empty() {
        return Ok(0);
    }
    let copied = write_partial(user_addr, bytes)?;
    Ok(copied.min(bytes.len()))
}

/// Encodes `value` into zero-padded ABI bytes and writes the complete ABI
/// representation to `user_addr`, returning `AxError::BadAddress` (`EFAULT`) on
/// short copy while preserving partial prefix writes.
pub fn write_user_value_with<T: IntoUserAbi>(
    user_addr: usize,
    value: &T,
    write_partial: impl FnMut(usize, &[u8]) -> AxResult<usize>,
) -> AxResult<()> {
    let expected = abi_size_of::<T>();
    if write_user_value_partial_with(user_addr, value, write_partial)? == expected {
        Ok(())
    } else {
        Err(AxError::BadAddress)
    }
}

const STACK_ABI_READ_BYTES: usize = 512;

fn with_raw_user_abi_bytes<T: UserAbiType, R>(
    user_addr: usize,
    count: usize,
    mut read_partial: impl FnMut(usize, &mut [u8]) -> AxResult<usize>,
    decode_all: impl FnOnce(&[u8]) -> AxResult<R>,
) -> AxResult<R> {
    let total_bytes = checked_abi_array_size::<T>(count)?;
    if total_bytes == 0 {
        return decode_all(&[]);
    }
    user_addr
        .checked_add(total_bytes)
        .ok_or(AxError::BadAddress)?;

    if total_bytes <= STACK_ABI_READ_BYTES {
        let mut stack_buf = [0u8; STACK_ABI_READ_BYTES];
        let raw = &mut stack_buf[..total_bytes];
        if read_partial(user_addr, raw)? != total_bytes {
            return Err(AxError::BadAddress);
        }
        decode_all(raw)
    } else {
        let mut heap_buf = Vec::new();
        if heap_buf.try_reserve_exact(total_bytes).is_err() {
            return Err(AxError::NoMemory);
        }
        heap_buf.resize(total_bytes, 0);
        if read_partial(user_addr, &mut heap_buf)? != total_bytes {
            return Err(AxError::BadAddress);
        }
        decode_all(&heap_buf)
    }
}

/// Reads and validates `dst.len()` contiguous ABI elements into `dst`.
///
/// Copies the complete byte range before decoding any element so `BadAddress`
/// (`EFAULT`) always precedes `InvalidInput` (`EINVAL`) and `dst` is untouched
/// on address/fault errors.
pub fn read_user_slice_with<T: FromUserAbi>(
    user_addr: usize,
    dst: &mut [T],
    read_partial: impl FnMut(usize, &mut [u8]) -> AxResult<usize>,
) -> AxResult<()> {
    with_raw_user_abi_bytes::<T, ()>(user_addr, dst.len(), read_partial, |raw| {
        let mut reader = AbiReader::new(raw);
        for slot in dst.iter_mut() {
            *slot = reader.read::<T>().map_err(AxError::from)?;
        }
        Ok(())
    })
}

/// Allocates with fallible `try_reserve_exact` and reads `count` validated ABI
/// elements from `user_addr`.
///
/// Copies the complete byte range before decoding any element so `BadAddress`
/// (`EFAULT`) always precedes `InvalidInput` (`EINVAL`).
pub fn read_user_array_with<T: FromUserAbi>(
    user_addr: usize,
    count: usize,
    read_partial: impl FnMut(usize, &mut [u8]) -> AxResult<usize>,
) -> AxResult<Vec<T>> {
    with_raw_user_abi_bytes::<T, Vec<T>>(user_addr, count, read_partial, |raw| {
        if count == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        if out.try_reserve_exact(count).is_err() {
            return Err(AxError::NoMemory);
        }
        let mut reader = AbiReader::new(raw);
        for _ in 0..count {
            out.push(reader.read::<T>().map_err(AxError::from)?);
        }
        Ok(out)
    })
}

/// Encodes and writes `values` element-by-element to `user_addr`, preserving
/// partial prefix writes on fault and returning `AxError::BadAddress` (`EFAULT`).
pub fn write_user_slice_with<T: IntoUserAbi>(
    user_addr: usize,
    values: &[T],
    mut write_partial: impl FnMut(usize, &[u8]) -> AxResult<usize>,
) -> AxResult<()> {
    let _total_bytes = checked_abi_array_size::<T>(values.len())?;
    if values.is_empty() {
        return Ok(());
    }
    let elem_size = abi_size_of::<T>();
    for (idx, value) in values.iter().enumerate() {
        let addr = user_addr
            .checked_add(idx * elem_size)
            .ok_or(AxError::BadAddress)?;
        write_user_value_with(addr, value, &mut write_partial)?;
    }
    Ok(())
}

macro_rules! impl_int_abi {
    ($($ty:ty),+ $(,)?) => {
        $(
            const _: () = {
                assert!(
                    core::mem::size_of::<$ty>()
                        == <[u8; core::mem::size_of::<$ty>()] as AbiByteBuffer>::LEN
                );
            };

            impl UserAbiType for $ty {
                type Buffer = [u8; core::mem::size_of::<$ty>()];
            }

            impl FromUserAbi for $ty {
                #[inline]
                fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
                    let slice = reader.take_exact(core::mem::size_of::<$ty>())?;
                    let mut raw = [0u8; core::mem::size_of::<$ty>()];
                    raw.copy_from_slice(slice);
                    Ok(<$ty>::from_ne_bytes(raw))
                }
            }

            impl IntoUserAbi for $ty {
                #[inline]
                fn encode_abi(&self, writer: &mut AbiWriter<'_>) {
                    writer
                        .take_exact_mut(core::mem::size_of::<$ty>())
                        .copy_from_slice(&self.to_ne_bytes());
                }
            }
        )+
    };
}

impl_int_abi!(
    u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, usize, isize
);

impl UserAbiType for () {
    type Buffer = [u8; 0];
}

impl FromUserAbi for () {
    #[inline]
    fn decode_abi(_reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
        Ok(())
    }
}

impl IntoUserAbi for () {
    #[inline]
    fn encode_abi(&self, _writer: &mut AbiWriter<'_>) {}
}

impl<const N: usize> UserAbiType for [u8; N] {
    type Buffer = [u8; N];
}

impl<const N: usize> FromUserAbi for [u8; N] {
    #[inline]
    fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
        let slice = reader.take_exact(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }
}

impl<const N: usize> IntoUserAbi for [u8; N] {
    #[inline]
    fn encode_abi(&self, writer: &mut AbiWriter<'_>) {
        writer.take_exact_mut(N).copy_from_slice(self);
    }
}

/// Implements `UserAbiType`, `FromUserAbi`, and `IntoUserAbi` for a fixed-size
/// array `[Elem; LEN]` without heap allocation.
#[macro_export]
macro_rules! impl_user_abi_fixed_array {
    ($elem:ty, $len:literal) => {
        impl $crate::UserAbiType for [$elem; $len] {
            type Buffer = [u8; core::mem::size_of::<[$elem; $len]>()];
        }

        const _: () = {
            assert!(core::mem::size_of::<[$elem; $len]>() == $len * $crate::abi_size_of::<$elem>());
        };

        impl $crate::FromUserAbi for [$elem; $len] {
            fn decode_abi(
                reader: &mut $crate::AbiReader<'_>,
            ) -> Result<Self, $crate::AbiDecodeError> {
                let mut first_err: Option<$crate::AbiDecodeError> = None;
                let mut slots: [Option<$elem>; $len] = core::array::from_fn(|_| {
                    if first_err.is_some() {
                        return None;
                    }
                    match reader.read::<$elem>() {
                        Ok(val) => Some(val),
                        Err(err) => {
                            first_err = Some(err);
                            None
                        }
                    }
                });
                if let Some(err) = first_err {
                    return Err(err);
                }
                Ok(core::array::from_fn(|idx| {
                    slots[idx]
                        .take()
                        .expect("all fixed-array elements decoded when first_err is None")
                }))
            }
        }

        impl $crate::IntoUserAbi for [$elem; $len] {
            fn encode_abi(&self, writer: &mut $crate::AbiWriter<'_>) {
                for item in self {
                    writer.write(item);
                }
            }
        }
    };
}

impl_user_abi_fixed_array!(i32, 2);
impl_user_abi_fixed_array!(u32, 2);
impl_user_abi_fixed_array!(i64, 2);
impl_user_abi_fixed_array!(u64, 2);
impl_user_abi_fixed_array!(usize, 2);
impl_user_abi_fixed_array!(u64, 16);

impl UserAbiType for bool {
    type Buffer = [u8; 1];
}

impl FromUserAbi for bool {
    #[inline]
    fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
        match reader.read::<u8>()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AbiDecodeError::InvalidRepresentation),
        }
    }
}

impl IntoUserAbi for bool {
    #[inline]
    fn encode_abi(&self, writer: &mut AbiWriter<'_>) {
        writer.write(&u8::from(*self));
    }
}

impl UserAbiType for char {
    type Buffer = [u8; 4];
}

impl FromUserAbi for char {
    #[inline]
    fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
        let code = reader.read::<u32>()?;
        char::from_u32(code).ok_or(AbiDecodeError::InvalidRepresentation)
    }
}

impl IntoUserAbi for char {
    #[inline]
    fn encode_abi(&self, writer: &mut AbiWriter<'_>) {
        writer.write(&u32::from(*self));
    }
}

macro_rules! impl_nonzero_abi {
    ($($nz:ty => $prim:ty),+ $(,)?) => {
        $(
            impl UserAbiType for $nz {
                type Buffer = <$prim as UserAbiType>::Buffer;
            }

            impl FromUserAbi for $nz {
                #[inline]
                fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
                    let raw = reader.read::<$prim>()?;
                    <$nz>::new(raw).ok_or(AbiDecodeError::InvalidRepresentation)
                }
            }

            impl IntoUserAbi for $nz {
                #[inline]
                fn encode_abi(&self, writer: &mut AbiWriter<'_>) {
                    writer.write(&self.get());
                }
            }
        )+
    };
}

impl_nonzero_abi!(
    core::num::NonZeroU8 => u8,
    core::num::NonZeroI8 => i8,
    core::num::NonZeroU16 => u16,
    core::num::NonZeroI16 => i16,
    core::num::NonZeroU32 => u32,
    core::num::NonZeroI32 => i32,
    core::num::NonZeroU64 => u64,
    core::num::NonZeroI64 => i64,
    core::num::NonZeroU128 => u128,
    core::num::NonZeroI128 => i128,
    core::num::NonZeroUsize => usize,
    core::num::NonZeroIsize => isize,
);

/// Implements `UserAbiType`, `FromUserAbi`, and `IntoUserAbi` for a C-ABI enum
/// with explicit discriminant validation.
#[macro_export]
macro_rules! impl_user_abi_enum {
    (
        for $ty:ty : $repr:ty {
            $($variant:path = $disc:literal),+ $(,)?
        }
    ) => {
        const _: () = {
            assert!(core::mem::size_of::<$ty>() == core::mem::size_of::<$repr>());
        };

        impl $crate::UserAbiType for $ty {
            type Buffer = <$repr as $crate::UserAbiType>::Buffer;
        }

        impl $crate::FromUserAbi for $ty {
            fn decode_abi(
                reader: &mut $crate::AbiReader<'_>,
            ) -> Result<Self, $crate::AbiDecodeError> {
                let raw = reader.read::<$repr>()?;
                match raw {
                    $($disc => Ok($variant),)+
                    _ => Err($crate::AbiDecodeError::InvalidRepresentation),
                }
            }
        }

        impl $crate::IntoUserAbi for $ty {
            fn encode_abi(&self, writer: &mut $crate::AbiWriter<'_>) {
                let raw: $repr = match *self {
                    $($variant => $disc,)+
                };
                writer.write(&raw);
            }
        }
    };
}

const _: () = {
    assert!(core::mem::size_of::<*const core::ffi::c_void>() == core::mem::size_of::<usize>());
    assert!(core::mem::size_of::<*mut core::ffi::c_void>() == core::mem::size_of::<usize>());
};

impl UserAbiType for *const core::ffi::c_void {
    type Buffer = <usize as UserAbiType>::Buffer;
}

impl FromUserAbi for *const core::ffi::c_void {
    #[inline]
    fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
        Ok(core::ptr::without_provenance(reader.read::<usize>()?))
    }
}

impl IntoUserAbi for *const core::ffi::c_void {
    #[inline]
    fn encode_abi(&self, writer: &mut AbiWriter<'_>) {
        writer.write(&(*self).addr());
    }
}

impl UserAbiType for *mut core::ffi::c_void {
    type Buffer = <usize as UserAbiType>::Buffer;
}

impl FromUserAbi for *mut core::ffi::c_void {
    #[inline]
    fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
        Ok(core::ptr::without_provenance_mut(reader.read::<usize>()?))
    }
}

impl IntoUserAbi for *mut core::ffi::c_void {
    #[inline]
    fn encode_abi(&self, writer: &mut AbiWriter<'_>) {
        writer.write(&(*self).addr());
    }
}

#[doc(hidden)]
#[inline]
pub fn decode_field_at<F: FromUserAbi>(bytes: &[u8], offset: usize) -> Result<F, AbiDecodeError> {
    let len = abi_size_of::<F>();
    let end = offset
        .checked_add(len)
        .ok_or(AbiDecodeError::UnexpectedLength {
            expected: len,
            actual: bytes.len().saturating_sub(offset),
        })?;
    let slice = bytes
        .get(offset..end)
        .ok_or(AbiDecodeError::UnexpectedLength {
            expected: len,
            actual: bytes.len().saturating_sub(offset),
        })?;
    decode_from_bytes(slice)
}

#[doc(hidden)]
#[inline]
pub fn encode_field_at<F: IntoUserAbi>(bytes: &mut [u8], offset: usize, value: &F) {
    let len = abi_size_of::<F>();
    let end = offset
        .checked_add(len)
        .expect("struct field ABI offset overflowed");
    encode_into_slice(value, &mut bytes[offset..end]);
}

/// Implements `UserAbiType`, `FromUserAbi`, and `IntoUserAbi` for a `#[repr(C)]`
/// struct using field-wise offset decoding and zero-padded field-wise encoding.
///
/// Exhaustive struct construction and destructuring, explicit ABI size checks,
/// and monotonically non-overlapping field offset assertions enforce at compile
/// time that every field of `$ty` is accounted for in C layout order and that
/// uninitialized Rust padding bytes are never read:
///
/// ```compile_fail
/// #[repr(C)]
/// struct IncompleteAbi {
///     first: u32,
///     second: u32,
/// }
/// pulse_user_abi::impl_user_abi_struct! {
///     for IncompleteAbi, size = 8 => {
///         first: u32,
///     }
/// }
/// ```
///
/// ```compile_fail
/// struct ReorderedRustLayout {
///     tag: u8,
///     word: u64,
/// }
/// pulse_user_abi::impl_user_abi_struct! {
///     for ReorderedRustLayout, size = 16 => {
///         tag: u8,
///         word: u64,
///     }
/// }
/// ```
#[macro_export]
macro_rules! impl_user_abi_struct {
    (
        for $ty:ty, size = $expected_size:expr => {
            $($field:ident : $fty:ty),+ $(,)?
        }
    ) => {
        const _: () = {
            assert!(core::mem::size_of::<$ty>() == ($expected_size));
            let mut cursor = 0usize;
            $(
                assert!(core::mem::size_of::<$fty>() == $crate::abi_size_of::<$fty>());
                let off = core::mem::offset_of!($ty, $field);
                assert!(
                    off >= cursor,
                    "impl_user_abi_struct fields must follow non-overlapping #[repr(C)] layout order"
                );
                cursor = off + $crate::abi_size_of::<$fty>();
                assert!(cursor <= ($expected_size));
            )+
        };

        impl $crate::UserAbiType for $ty {
            type Buffer = [u8; $expected_size];
        }

        impl $crate::FromUserAbi for $ty {
            fn decode_abi(
                reader: &mut $crate::AbiReader<'_>,
            ) -> Result<Self, $crate::AbiDecodeError> {
                let raw = reader.take_exact($expected_size)?;
                Ok(Self {
                    $(
                        $field: $crate::decode_field_at::<$fty>(
                            raw,
                            core::mem::offset_of!($ty, $field),
                        )?,
                    )+
                })
            }
        }

        impl $crate::IntoUserAbi for $ty {
            fn encode_abi(&self, writer: &mut $crate::AbiWriter<'_>) {
                let Self { $(ref $field),+ } = *self;
                let dst = writer.take_exact_mut($expected_size);
                dst.fill(0);
                $(
                    $crate::encode_field_at::<$fty>(
                        dst,
                        core::mem::offset_of!($ty, $field),
                        $field,
                    );
                )+
            }
        }
    };
}

mod linux_abi_impls {
    use linux_raw_sys::{
        ctypes::{c_int, c_long, c_short, c_void},
        general::{
            __kernel_off_t, __kernel_old_time_t, __kernel_pid_t, __kernel_size_t,
            __kernel_suseconds_t, __u64, flock, iovec, itimerspec, itimerval, pollfd, rlimit64,
            sigaltstack, timespec, timeval,
        },
    };

    crate::impl_user_abi_struct! {
        for timespec, size = 16 => {
            tv_sec: __kernel_old_time_t,
            tv_nsec: c_long,
        }
    }

    crate::impl_user_abi_struct! {
        for timeval, size = 16 => {
            tv_sec: __kernel_old_time_t,
            tv_usec: __kernel_suseconds_t,
        }
    }

    crate::impl_user_abi_struct! {
        for itimerspec, size = 32 => {
            it_interval: timespec,
            it_value: timespec,
        }
    }

    crate::impl_user_abi_struct! {
        for itimerval, size = 32 => {
            it_interval: timeval,
            it_value: timeval,
        }
    }

    crate::impl_user_abi_struct! {
        for iovec, size = 16 => {
            iov_base: *mut c_void,
            iov_len: __kernel_size_t,
        }
    }

    crate::impl_user_abi_struct! {
        for flock, size = 32 => {
            l_type: c_short,
            l_whence: c_short,
            l_start: __kernel_off_t,
            l_len: __kernel_off_t,
            l_pid: __kernel_pid_t,
        }
    }

    crate::impl_user_abi_struct! {
        for sigaltstack, size = 24 => {
            ss_sp: *mut c_void,
            ss_flags: c_int,
            ss_size: __kernel_size_t,
        }
    }

    crate::impl_user_abi_struct! {
        for pollfd, size = 8 => {
            fd: c_int,
            events: c_short,
            revents: c_short,
        }
    }

    crate::impl_user_abi_struct! {
        for rlimit64, size = 16 => {
            rlim_cur: __u64,
            rlim_max: __u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use axerrno::{AxError, LinuxError};

    use super::*;

    #[test]
    fn primitive_scalars_preserve_linux_abi_sizes_and_native_byte_order() {
        assert_eq!(abi_size_of::<u8>(), 1);
        assert_eq!(abi_size_of::<i8>(), 1);
        assert_eq!(abi_size_of::<u16>(), 2);
        assert_eq!(abi_size_of::<i16>(), 2);
        assert_eq!(abi_size_of::<u32>(), 4);
        assert_eq!(abi_size_of::<i32>(), 4);
        assert_eq!(abi_size_of::<u64>(), 8);
        assert_eq!(abi_size_of::<i64>(), 8);
        assert_eq!(abi_size_of::<u128>(), 16);
        assert_eq!(abi_size_of::<i128>(), 16);
        assert_eq!(abi_size_of::<usize>(), core::mem::size_of::<usize>());
        assert_eq!(abi_size_of::<isize>(), core::mem::size_of::<isize>());

        let raw_u32 = 0x1234_5678u32.to_ne_bytes();
        assert_eq!(decode_from_bytes::<u32>(&raw_u32), Ok(0x1234_5678));
        assert_eq!(encode_to_buffer(&0x1234_5678u32), raw_u32);

        let raw_i64 = (-0x0102_0304_0506_0708i64).to_ne_bytes();
        assert_eq!(
            decode_from_bytes::<i64>(&raw_i64),
            Ok(-0x0102_0304_0506_0708)
        );
        assert_eq!(encode_to_buffer(&-0x0102_0304_0506_0708i64), raw_i64);

        let err = decode_from_bytes::<u32>(&[1, 2, 3]).unwrap_err();
        assert_eq!(
            err,
            AbiDecodeError::UnexpectedLength {
                expected: 4,
                actual: 3
            }
        );
        assert_eq!(AxError::from(err), AxError::InvalidInput);
        assert_eq!(LinuxError::from(err), LinuxError::EINVAL);
    }

    #[repr(u32)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SampleAbiMode {
        Read      = 1,
        Write     = 2,
        ReadWrite = 3,
    }

    crate::impl_user_abi_enum! {
        for SampleAbiMode: u32 {
            SampleAbiMode::Read = 1,
            SampleAbiMode::Write = 2,
            SampleAbiMode::ReadWrite = 3,
        }
    }

    #[test]
    fn invalid_rust_representations_are_refused() {
        assert_eq!(abi_size_of::<bool>(), 1);
        assert_eq!(decode_from_bytes::<bool>(&[0]), Ok(false));
        assert_eq!(decode_from_bytes::<bool>(&[1]), Ok(true));
        assert_eq!(encode_to_buffer(&false), [0u8]);
        assert_eq!(encode_to_buffer(&true), [1u8]);
        for bad_bool in [2u8, 3, 0x7f, 0x80, 0xff] {
            assert_eq!(
                decode_from_bytes::<bool>(&[bad_bool]),
                Err(AbiDecodeError::InvalidRepresentation),
            );
        }

        use core::num::{NonZeroI64, NonZeroU32, NonZeroUsize};
        assert_eq!(
            decode_from_bytes::<NonZeroU32>(&0u32.to_ne_bytes()),
            Err(AbiDecodeError::InvalidRepresentation),
        );
        assert_eq!(
            decode_from_bytes::<NonZeroU32>(&7u32.to_ne_bytes()),
            Ok(NonZeroU32::new(7).unwrap()),
        );
        assert_eq!(
            encode_to_buffer(&NonZeroU32::new(7).unwrap()),
            7u32.to_ne_bytes()
        );
        assert_eq!(
            decode_from_bytes::<NonZeroI64>(&0i64.to_ne_bytes()),
            Err(AbiDecodeError::InvalidRepresentation),
        );
        assert_eq!(
            decode_from_bytes::<NonZeroUsize>(&0usize.to_ne_bytes()),
            Err(AbiDecodeError::InvalidRepresentation),
        );

        assert_eq!(decode_from_bytes::<char>(&0x41u32.to_ne_bytes()), Ok('A'));
        assert_eq!(
            decode_from_bytes::<char>(&0xD800u32.to_ne_bytes()),
            Err(AbiDecodeError::InvalidRepresentation),
        );
        assert_eq!(
            decode_from_bytes::<char>(&0x0011_0000u32.to_ne_bytes()),
            Err(AbiDecodeError::InvalidRepresentation),
        );

        assert_eq!(
            decode_from_bytes::<SampleAbiMode>(&2u32.to_ne_bytes()),
            Ok(SampleAbiMode::Write),
        );
        assert_eq!(
            encode_to_buffer(&SampleAbiMode::ReadWrite),
            3u32.to_ne_bytes()
        );
        for invalid_tag in [0u32, 4, u32::MAX] {
            let err = decode_from_bytes::<SampleAbiMode>(&invalid_tag.to_ne_bytes()).unwrap_err();
            assert_eq!(err, AbiDecodeError::InvalidRepresentation);
            assert_eq!(LinuxError::from(err), LinuxError::EINVAL);
        }
    }

    #[test]
    fn zero_sized_values_and_fixed_byte_arrays_round_trip() {
        assert_eq!(abi_size_of::<()>(), 0);
        assert_eq!(decode_from_bytes::<()>(&[]), Ok(()));
        assert_eq!(encode_to_buffer(&()), [0u8; 0]);
        assert_eq!(
            decode_from_bytes::<()>(&[1]),
            Err(AbiDecodeError::UnexpectedLength {
                expected: 0,
                actual: 1
            })
        );

        assert_eq!(abi_size_of::<[u8; 0]>(), 0);
        assert_eq!(decode_from_bytes::<[u8; 0]>(&[]), Ok([]));
        assert_eq!(encode_to_buffer(&[0u8; 0]), [0u8; 0]);

        let bytes65 = [0x5Au8; 65];
        assert_eq!(abi_size_of::<[u8; 65]>(), 65);
        assert_eq!(decode_from_bytes::<[u8; 65]>(&bytes65), Ok(bytes65));
        assert_eq!(encode_to_buffer(&bytes65), bytes65);

        let fds = [3i32, 4i32];
        let mut expected_fds = [0u8; 8];
        expected_fds[0..4].copy_from_slice(&3i32.to_ne_bytes());
        expected_fds[4..8].copy_from_slice(&4i32.to_ne_bytes());
        assert_eq!(abi_size_of::<[i32; 2]>(), 8);
        assert_eq!(encode_to_buffer(&fds), expected_fds);
        assert_eq!(decode_from_bytes::<[i32; 2]>(&expected_fds), Ok(fds));
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct PaddedValidatedAbi {
        enabled: bool,
        // 3 bytes of implicit padding (1..4)
        mode: SampleAbiMode,
        tag: u8,
        // 7 bytes of implicit padding (9..16)
        cookie: u64,
    }

    crate::impl_user_abi_struct! {
        for PaddedValidatedAbi, size = 24 => {
            enabled: bool,
            mode: SampleAbiMode,
            tag: u8,
            cookie: u64,
        }
    }

    #[test]
    fn padded_linux_flock_encodes_zero_padding_and_decodes_ignoring_user_padding_bytes() {
        use linux_raw_sys::general::{flock, iovec, itimerspec, sigaltstack, timespec};

        assert_eq!(abi_size_of::<flock>(), 32);
        assert_eq!(abi_size_of::<flock>(), core::mem::size_of::<flock>());

        let lock = flock {
            l_type: 1,
            l_whence: 2,
            l_start: 0x0102_0304_0506_0708,
            l_len: 4096,
            l_pid: 1234,
        };

        // Pre-fill target slice with non-zero poison to verify padding slots are
        // deterministically zeroed without reading Rust struct padding.
        let mut encoded = [0xAAu8; 32];
        encode_into_slice(&lock, &mut encoded);

        assert_eq!(&encoded[0..2], &1i16.to_ne_bytes());
        assert_eq!(&encoded[2..4], &2i16.to_ne_bytes());
        assert_eq!(&encoded[4..8], &[0, 0, 0, 0]);
        assert_eq!(&encoded[8..16], &0x0102_0304_0506_0708i64.to_ne_bytes());
        assert_eq!(&encoded[16..24], &4096i64.to_ne_bytes());
        assert_eq!(&encoded[24..28], &1234i32.to_ne_bytes());
        assert_eq!(&encoded[28..32], &[0, 0, 0, 0]);

        // User-supplied bytes may carry arbitrary garbage in padding regions;
        // decoding must ignore padding and preserve field values.
        let mut user_raw = encoded;
        user_raw[4..8].fill(0xFF);
        user_raw[28..32].fill(0xCC);
        let decoded = decode_from_bytes::<flock>(&user_raw).unwrap();
        assert_eq!(decoded.l_type, 1);
        assert_eq!(decoded.l_whence, 2);
        assert_eq!(decoded.l_start, 0x0102_0304_0506_0708);
        assert_eq!(decoded.l_len, 4096);
        assert_eq!(decoded.l_pid, 1234);

        // Also verify sigaltstack (24 bytes with 4-byte interior padding at 12..16)
        // and pointer-bearing iovec / nested itimerspec.
        assert_eq!(abi_size_of::<sigaltstack>(), 24);
        let altstack = sigaltstack {
            ss_sp: core::ptr::without_provenance_mut(0x7fff_0000),
            ss_flags: 2,
            ss_size: 0x2000,
        };
        let ss_bytes = encode_to_buffer(&altstack);
        assert_eq!(&ss_bytes[12..16], &[0, 0, 0, 0]);
        let decoded_ss = decode_from_bytes::<sigaltstack>(&ss_bytes).unwrap();
        assert_eq!(decoded_ss.ss_sp as usize, 0x7fff_0000);
        assert_eq!(decoded_ss.ss_flags, 2);
        assert_eq!(decoded_ss.ss_size, 0x2000);

        let iov = iovec {
            iov_base: core::ptr::without_provenance_mut(0x4000),
            iov_len: 512,
        };
        let decoded_iov = decode_from_bytes::<iovec>(&encode_to_buffer(&iov)).unwrap();
        assert_eq!(decoded_iov.iov_base as usize, 0x4000);
        assert_eq!(decoded_iov.iov_len, 512);

        let timer = itimerspec {
            it_interval: timespec {
                tv_sec: 1,
                tv_nsec: 500,
            },
            it_value: timespec {
                tv_sec: 2,
                tv_nsec: 999,
            },
        };
        let decoded_timer = decode_from_bytes::<itimerspec>(&encode_to_buffer(&timer)).unwrap();
        assert_eq!(decoded_timer.it_interval.tv_sec, 1);
        assert_eq!(decoded_timer.it_interval.tv_nsec, 500);
        assert_eq!(decoded_timer.it_value.tv_sec, 2);
        assert_eq!(decoded_timer.it_value.tv_nsec, 999);
    }

    #[test]
    fn padded_validated_struct_refuses_invalid_inner_fields_and_zeroes_padding() {
        assert_eq!(abi_size_of::<PaddedValidatedAbi>(), 24);
        let val = PaddedValidatedAbi {
            enabled: true,
            mode: SampleAbiMode::Read,
            tag: 0x7E,
            cookie: 0xDEAD_BEEF_CAFE_BABE,
        };
        let raw = encode_to_buffer(&val);
        assert_eq!(raw[0], 1);
        assert_eq!(&raw[1..4], &[0, 0, 0]);
        assert_eq!(&raw[4..8], &1u32.to_ne_bytes());
        assert_eq!(raw[8], 0x7E);
        assert_eq!(&raw[9..16], &[0; 7]);
        assert_eq!(&raw[16..24], &0xDEAD_BEEF_CAFE_BABEu64.to_ne_bytes());
        assert_eq!(decode_from_bytes::<PaddedValidatedAbi>(&raw), Ok(val));

        let mut bad_bool_raw = raw;
        bad_bool_raw[0] = 2;
        assert_eq!(
            decode_from_bytes::<PaddedValidatedAbi>(&bad_bool_raw),
            Err(AbiDecodeError::InvalidRepresentation),
        );

        let mut bad_mode_raw = raw;
        bad_mode_raw[4..8].copy_from_slice(&99u32.to_ne_bytes());
        assert_eq!(
            decode_from_bytes::<PaddedValidatedAbi>(&bad_mode_raw),
            Err(AbiDecodeError::InvalidRepresentation),
        );
    }

    struct MockUserMemory {
        range: UserMemoryRange,
        mapped_start: usize,
        mapped: alloc::vec::Vec<u8>,
        access_calls: usize,
    }

    impl MockUserMemory {
        fn new(mapped_len: usize) -> Self {
            let range = UserMemoryRange::new(0x1000, 0x3f_ffff_f000).unwrap();
            Self {
                range,
                mapped_start: 0x2000,
                mapped: alloc::vec![0xCDu8; mapped_len],
                access_calls: 0,
            }
        }

        fn mapped_end(&self) -> usize {
            self.mapped_start + self.mapped.len()
        }

        fn read_partial(&mut self, user_addr: usize, dst: &mut [u8]) -> axerrno::AxResult<usize> {
            self.access_calls += 1;
            if dst.is_empty() {
                return Ok(0);
            }
            self.range.validate(user_addr, dst.len())?;
            if user_addr < self.mapped_start || user_addr >= self.mapped_end() {
                return Ok(0);
            }
            let available = (self.mapped_end() - user_addr).min(dst.len());
            let off = user_addr - self.mapped_start;
            dst[..available].copy_from_slice(&self.mapped[off..off + available]);
            Ok(available)
        }

        fn write_partial(&mut self, user_addr: usize, src: &[u8]) -> axerrno::AxResult<usize> {
            self.access_calls += 1;
            if src.is_empty() {
                return Ok(0);
            }
            self.range.validate(user_addr, src.len())?;
            if user_addr < self.mapped_start || user_addr >= self.mapped_end() {
                return Ok(0);
            }
            let available = (self.mapped_end() - user_addr).min(src.len());
            let off = user_addr - self.mapped_start;
            self.mapped[off..off + available].copy_from_slice(&src[..available]);
            Ok(available)
        }
    }

    #[test]
    fn checked_size_overflow_and_zero_sized_user_memory_transfers_behave_soundly() {
        assert_eq!(checked_abi_array_size::<u64>(0), Ok(0));
        assert_eq!(checked_abi_array_size::<u64>(4), Ok(32));
        assert_eq!(checked_abi_array_size::<()>(0), Ok(0));
        assert_eq!(checked_abi_array_size::<()>(16), Ok(0));

        // Arithmetic overflow on count * ABI_SIZE -> InvalidInput (EINVAL).
        for bad_count in [
            (isize::MAX as usize / 8) + 1,
            (usize::MAX / 8) + 1,
            usize::MAX,
        ] {
            let err = checked_abi_array_size::<u64>(bad_count).unwrap_err();
            assert_eq!(err, AxError::InvalidInput);
            assert_eq!(LinuxError::from(err.canonicalize()), LinuxError::EINVAL);
        }

        // Count exceeding isize::MAX is rejected even for zero-sized elements.
        assert_eq!(
            checked_abi_array_size::<()>((isize::MAX as usize) + 1),
            Err(AxError::InvalidInput),
        );

        let mut mem = MockUserMemory::new(64);
        assert_eq!(
            read_user_array_with::<u64>(0x2000, usize::MAX, |a, b| mem.read_partial(a, b)),
            Err(AxError::InvalidInput),
        );
        assert_eq!(
            read_user_array_with::<()>(0x2000, (isize::MAX as usize) + 1, |a, b| {
                mem.read_partial(a, b)
            }),
            Err(AxError::InvalidInput),
        );
        assert_eq!(
            read_user_array_with::<u64>(usize::MAX - 4, 2, |a, b| mem.read_partial(a, b)),
            Err(AxError::BadAddress),
        );
        let mut slice_dst = [7u32, 9u32];
        assert_eq!(
            read_user_slice_with::<u32>(usize::MAX - 4, &mut slice_dst, |a, b| {
                mem.read_partial(a, b)
            }),
            Err(AxError::BadAddress),
        );
        assert_eq!(slice_dst, [7u32, 9u32]);
        // Neither overflowing request touched user memory.
        assert_eq!(mem.access_calls, 0);

        // Zero-sized values and zero-length arrays succeed at 0 and usize::MAX
        // without dereferencing or invoking the byte-copy transport.
        for addr in [0usize, 0x2000, usize::MAX] {
            assert_eq!(
                read_user_value_with::<()>(addr, |a, b| mem.read_partial(a, b)),
                Ok(())
            );
            assert_eq!(
                write_user_value_with::<()>(addr, &(), |a, b| mem.write_partial(a, b)),
                Ok(())
            );
            assert_eq!(
                read_user_array_with::<u64>(addr, 0, |a, b| mem.read_partial(a, b)),
                Ok(alloc::vec::Vec::new())
            );
            assert_eq!(
                write_user_slice_with::<u64>(addr, &[], |a, b| mem.write_partial(a, b)),
                Ok(())
            );
        }
        assert_eq!(mem.access_calls, 0);
    }

    #[test]
    fn range_validation_partial_copy_and_errno_precedence_are_preserved() {
        use linux_raw_sys::general::flock;

        let range = UserMemoryRange::new(0x1000, 0x3f_ffff_f000).unwrap();
        assert_eq!(range.validate(0, 0), Ok(()));
        assert_eq!(range.validate(usize::MAX, 0), Ok(()));
        assert_eq!(range.validate(0, 1), Err(AxError::BadAddress));
        assert_eq!(range.validate(0x0fff, 1), Err(AxError::BadAddress));
        assert_eq!(range.validate(0x1000, 1), Ok(()));
        assert_eq!(range.validate(0x40_0000_0000 - 1, 1), Ok(()));
        assert_eq!(range.validate(0x40_0000_0000, 1), Err(AxError::BadAddress));
        assert_eq!(range.validate(usize::MAX, 2), Err(AxError::BadAddress));

        let mut mem = MockUserMemory::new(64);
        let mapped_end = mem.mapped_end();

        // Out-of-range pointer -> BadAddress (EFAULT).
        let err = read_user_value_with::<u32>(0, |a, b| mem.read_partial(a, b)).unwrap_err();
        assert_eq!(err, AxError::BadAddress);
        assert_eq!(LinuxError::from(err.canonicalize()), LinuxError::EFAULT);

        // Short read across mapped/unmapped boundary -> BadAddress (EFAULT)
        // BEFORE representation validation (even though prefix contains invalid
        // bool byte 0xCD), for single values, arrays, and slices alike.
        let short_addr = mapped_end - 8;
        let err =
            read_user_value_with::<PaddedValidatedAbi>(short_addr, |a, b| mem.read_partial(a, b))
                .unwrap_err();
        assert_eq!(err, AxError::BadAddress);
        assert_eq!(LinuxError::from(err.canonicalize()), LinuxError::EFAULT);

        assert_eq!(
            read_user_array_with::<bool>(mapped_end - 1, 2, |a, b| mem.read_partial(a, b)),
            Err(AxError::BadAddress),
        );
        let mut bool_dst = [false, true];
        assert_eq!(
            read_user_slice_with::<bool>(mapped_end - 1, &mut bool_dst, |a, b| {
                mem.read_partial(a, b)
            }),
            Err(AxError::BadAddress),
        );
        assert_eq!(bool_dst, [false, true]);

        // Full read of invalid representation -> InvalidInput (EINVAL).
        let err = read_user_value_with::<bool>(0x2000, |a, b| mem.read_partial(a, b)).unwrap_err();
        assert_eq!(err, AxError::InvalidInput);
        assert_eq!(LinuxError::from(err.canonicalize()), LinuxError::EINVAL);

        // Partial write of padded `flock` (32 bytes) across fault boundary at
        // mapped_end - 16 writes the first 16 ABI bytes (including zeroed
        // interior padding at 4..8) and returns BadAddress (EFAULT).
        let lock = flock {
            l_type: 3,
            l_whence: 1,
            l_start: 0x1122_3344_5566_7788,
            l_len: 8192,
            l_pid: 42,
        };
        let partial_write_addr = mapped_end - 16;
        let partial_copied = write_user_value_partial_with(partial_write_addr, &lock, |a, b| {
            mem.write_partial(a, b)
        })
        .unwrap();
        assert_eq!(partial_copied, 16);

        // Reset mapped tail to poison and test write_user_value_with returning EFAULT
        // while still writing the valid 16-byte prefix with zeroed padding.
        mem.mapped[48..64].fill(0xEE);
        let err = write_user_value_with(partial_write_addr, &lock, |a, b| mem.write_partial(a, b))
            .unwrap_err();
        assert_eq!(err, AxError::BadAddress);
        assert_eq!(&mem.mapped[48..50], &3i16.to_ne_bytes());
        assert_eq!(&mem.mapped[50..52], &1i16.to_ne_bytes());
        assert_eq!(&mem.mapped[52..56], &[0, 0, 0, 0]);
        assert_eq!(&mem.mapped[56..64], &0x1122_3344_5566_7788i64.to_ne_bytes());

        // Multi-element array write spanning the fault boundary writes earlier
        // elements before returning EFAULT on the faulting element.
        let values = [0x1111_2222_3333_4444u64, 0x5555_6666_7777_8888u64];
        let array_boundary_addr = mapped_end - 8;
        let err =
            write_user_slice_with(array_boundary_addr, &values, |a, b| mem.write_partial(a, b))
                .unwrap_err();
        assert_eq!(err, AxError::BadAddress);
        assert_eq!(&mem.mapped[56..64], &0x1111_2222_3333_4444u64.to_ne_bytes());
    }
}
