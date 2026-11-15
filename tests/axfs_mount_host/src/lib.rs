//! Host contract tests for the production mount coordinator and VFS.
extern crate alloc;

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../modules/axfs/src/mounts.rs"]
mod mounts;

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod tests;
