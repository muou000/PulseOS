use axplat::tlb::TlbIf;

struct TlbIfImpl;

#[impl_plat_interface]
impl TlbIf for TlbIfImpl {
    fn requires_global_sfence() -> bool {
        false
    }
}
