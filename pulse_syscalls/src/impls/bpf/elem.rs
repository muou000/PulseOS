use alloc::vec::Vec;
use axerrno::LinuxError;
use bpf::{BPF_EXIST, BpfMap};

use super::abi::BpfMapElemAttr;

const BPF_MAP_MAX_KEY_SIZE: usize = bpf::BPF_MAP_MAX_KEY_SIZE as usize;
const BPF_MAP_MAX_VALUE_SIZE: usize = bpf::BPF_MAP_MAX_VALUE_SIZE as usize;

pub fn copy_from_user<R>(
    user_addr: usize,
    len: usize,
    max_len: usize,
    mut read_user: R,
) -> Result<Vec<u8>, LinuxError>
where
    R: FnMut(usize, &mut [u8]) -> Result<(), LinuxError>,
{
    if user_addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    if len == 0 || len > max_len {
        return Err(LinuxError::EINVAL);
    }
    let mut buf = alloc::vec![0u8; len];
    read_user(user_addr, &mut buf)?;
    Ok(buf)
}

pub fn copy_to_user<W>(
    user_addr: usize,
    bytes: &[u8],
    max_len: usize,
    mut write_user: W,
) -> Result<(), LinuxError>
where
    W: FnMut(usize, &[u8]) -> Result<(), LinuxError>,
{
    if user_addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    if bytes.is_empty() || bytes.len() > max_len {
        return Err(LinuxError::EINVAL);
    }
    write_user(user_addr, bytes)
}

pub fn bpf_map_lookup_elem<R, W>(
    map: &BpfMap,
    attr: &BpfMapElemAttr,
    read_user: R,
    write_user: W,
) -> Result<isize, LinuxError>
where
    R: FnMut(usize, &mut [u8]) -> Result<(), LinuxError>,
    W: FnMut(usize, &[u8]) -> Result<(), LinuxError>,
{
    if attr.flags != 0 {
        return Err(LinuxError::EINVAL);
    }
    let key_size = map.spec().key_size() as usize;
    let val_size = map.spec().value_size() as usize;

    let key = copy_from_user(attr.key as usize, key_size, BPF_MAP_MAX_KEY_SIZE, read_user)?;
    let mut val = alloc::vec![0u8; val_size];
    map.lookup(&key, &mut val)?;
    copy_to_user(attr.value_or_next_key as usize, &val, BPF_MAP_MAX_VALUE_SIZE, write_user)?;
    Ok(0)
}

pub fn bpf_map_update_elem<R>(
    map: &BpfMap,
    attr: &BpfMapElemAttr,
    mut read_user: R,
) -> Result<isize, LinuxError>
where
    R: FnMut(usize, &mut [u8]) -> Result<(), LinuxError>,
{
    let key_size = map.spec().key_size() as usize;
    let val_size = map.spec().value_size() as usize;

    let key = copy_from_user(attr.key as usize, key_size, BPF_MAP_MAX_KEY_SIZE, &mut read_user)?;
    let val = copy_from_user(attr.value_or_next_key as usize, val_size, BPF_MAP_MAX_VALUE_SIZE, &mut read_user)?;
    if attr.flags > BPF_EXIST {
        return Err(LinuxError::EINVAL);
    }
    map.update(&key, &val, attr.flags)?;
    Ok(0)
}

pub fn bpf_map_delete_elem<R>(
    map: &BpfMap,
    attr: &BpfMapElemAttr,
    read_user: R,
) -> Result<isize, LinuxError>
where
    R: FnMut(usize, &mut [u8]) -> Result<(), LinuxError>,
{
    if attr.flags != 0 || attr.value_or_next_key != 0 {
        return Err(LinuxError::EINVAL);
    }
    let key_size = map.spec().key_size() as usize;
    let key = copy_from_user(attr.key as usize, key_size, BPF_MAP_MAX_KEY_SIZE, read_user)?;
    map.delete(&key)?;
    Ok(0)
}

pub fn bpf_map_get_next_key<R, W>(
    map: &BpfMap,
    attr: &BpfMapElemAttr,
    read_user: R,
    write_user: W,
) -> Result<isize, LinuxError>
where
    R: FnMut(usize, &mut [u8]) -> Result<(), LinuxError>,
    W: FnMut(usize, &[u8]) -> Result<(), LinuxError>,
{
    if attr.flags != 0 {
        return Err(LinuxError::EINVAL);
    }
    let key_size = map.spec().key_size() as usize;
    let key = if attr.key == 0 {
        None
    } else {
        Some(copy_from_user(attr.key as usize, key_size, BPF_MAP_MAX_KEY_SIZE, read_user)?)
    };

    let mut next_key = alloc::vec![0u8; key_size];
    map.get_next_key(key.as_deref(), &mut next_key)?;
    copy_to_user(attr.value_or_next_key as usize, &next_key, BPF_MAP_MAX_KEY_SIZE, write_user)?;
    Ok(0)
}
