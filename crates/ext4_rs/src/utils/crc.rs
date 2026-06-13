/* */
/* CRC LOOKUP TABLE */
/* ================ */
/* The following CRC lookup table was generated automagically */
/* by the Rocksoft^tm Model CRC Algorithm Table Generation */
/* Program V1.0 using the following model parameters: */
/* */
/* Width : 4 bytes. */
/* Poly : 0x1EDC6F41L */
/* Reverse : TRUE. */
/* */
/* For more information on the Rocksoft^tm Model CRC Algorithm, */
/* see the document titled "A Painless Guide to CRC Error */
/* Detection Algorithms" by Ross Williams */
/* (ross@guest.adelaide.edu.au.). This document is likely to be */
/* in the FTP archive "ftp.adelaide.edu.au/pub/rocksoft". */
/* */
include!("crc_table.rs");

pub const EXT4_CRC32_INIT: u32 = 0xFFFFFFFF;

/// Calculate CRC32 checksum
/// Parameter crc: Initial value
/// Parameter buf: Buffer
/// Parameter size: Buffer size
/// Parameter tab: Lookup table
pub fn crc32(crc: u32, buf: &[u8], _size: u32, _tab: &[u32]) -> u32 {
    let mut crc = crc;
    let mut p = buf;

    while p.len() >= 8 {
        let n = u32::from_le_bytes([p[0], p[1], p[2], p[3]]) ^ crc;
        let m = u32::from_le_bytes([p[4], p[5], p[6], p[7]]);
        crc = CRC32C_TAB8[7][(n & 0xFF) as usize] ^
              CRC32C_TAB8[6][((n >> 8) & 0xFF) as usize] ^
              CRC32C_TAB8[5][((n >> 16) & 0xFF) as usize] ^
              CRC32C_TAB8[4][((n >> 24) & 0xFF) as usize] ^
              CRC32C_TAB8[3][(m & 0xFF) as usize] ^
              CRC32C_TAB8[2][((m >> 8) & 0xFF) as usize] ^
              CRC32C_TAB8[1][((m >> 16) & 0xFF) as usize] ^
              CRC32C_TAB8[0][((m >> 24) & 0xFF) as usize];
        p = &p[8..];
    }

    for &b in p {
        crc = CRC32C_TAB8[0][((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }

    crc
}

pub fn ext4_crc32c(crc: u32, buf: &[u8], _size: u32) -> u32 {
    crc32(crc, buf, 0, &[])
}