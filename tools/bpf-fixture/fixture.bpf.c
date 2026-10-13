/* Pinned fixed-layout BPF fixture for PulseOS libbpf workflow.
 *
 * This fixture contains fixed-layout tracepoint and perf_event sections,
 * supported Map-FD relocations, and no BTF/CO-RE metadata.
 */

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef long long __s64;
typedef int __s32;

#define SEC(name) __attribute__((section(name), used))

/* Classic struct bpf_map_def for fixed-layout ELF map declaration */
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
};

/* BPF Helper function prototypes */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) __attribute__((unused)) = (void *)1;
static __s64 (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) __attribute__((unused)) = (void *)2;
static __u64 (*bpf_ktime_get_ns)(void) __attribute__((unused)) = (void *)5;
static __s64 (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) __attribute__((unused)) = (void *)25;

#define BPF_F_CURRENT_CPU 0xFFFFFFFFULL

/* Map definitions */
SEC("maps")
struct bpf_map_def counters = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 16,
    .map_flags = 0,
};

SEC("maps")
struct bpf_map_def events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 64,
    .map_flags = 0,
};

/* Tracepoint context representation for sched_switch */
struct sched_switch_args {
    __u64 pad;
    __u32 prev_pid;
    __u32 next_pid;
    __u64 prev_state;
};

/* Normalized sample event record structure */
struct sample_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 cpu;
    __u32 event_id;
    __u32 value;
};

/* Tracepoint program: increments counter map on sched_switch */
SEC("tracepoint/sched/sched_switch")
int tracepoint__sched__sched_switch(struct sched_switch_args *ctx) {
    (void)ctx;
    __u32 key = 0;
    __u64 *val = (__u64 *)bpf_map_lookup_elem(&counters, &key);
    if (val) {
        *val = *val + 1;
    }
    return 0;
}

/* Perf event sample context */
struct bpf_perf_event_data {
    __u64 sample_period;
    __u64 addr;
};

/* Perf event program: records sample and outputs to perf buffer */
SEC("perf_event")
int bpf_perf_event_handler(struct bpf_perf_event_data *ctx) {
    __u32 key = 1;
    __u64 *val = (__u64 *)bpf_map_lookup_elem(&counters, &key);
    if (val) {
        *val = *val + 1;
    }

    struct sample_event ev = {0};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.event_id = 1;
    ev.value = (__u32)ctx->sample_period;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}
