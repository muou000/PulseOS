# Failed exec with a live sibling

Build the probe and a dynamically linked executable whose ELF interpreter is
absent from the guest. Set `CC` to the target's Linux C compiler (for example
`riscv64-linux-gnu-gcc` or `loongarch64-linux-gnu-gcc`) and `IMAGE` to a
private copy of that architecture's test rootfs. Run from the repository root.

```sh
run_dir=$(mktemp -d)
"$CC" -O2 -Wall -Wextra -Werror -static -pthread tests/exec/failed_prepare.c \
    -o "$run_dir/failed-prepare"
printf 'int main(void) { return 1; }\n' | \
    "$CC" -x c -Wl,--dynamic-linker=/pulse-missing-loader -o "$run_dir/missing-interpreter" -
readelf -lW "$run_dir/missing-interpreter" | grep 'Requesting program interpreter: /pulse-missing-loader]'
scripts/install_to_rootfs.sh "$IMAGE" "$run_dir/failed-prepare" "$run_dir/missing-interpreter" /opt/
```

Boot the image with its architecture's QEMU command from `AGENTS.md`. Run
`/opt/failed-prepare /opt/missing-interpreter` in the guest. The caller and a
sibling rendezvous before `execve`. Resolving the missing interpreter then
fails with `ENOENT` after the main ELF segments have been prepared. The test
requires both threads to rendezvous again in the original image, prints
`EXEC_PREPARE PASS`, and exits with status 0. A 15-second alarm bounds the wait
if the sibling exits prematurely.
