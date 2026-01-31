/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;

static const pid_t pid_filter = 0;
static const char *GOLD[2] = {
    "sshd",
    "cat",
};

struct event {
    __u32 pid;
    char comm[TASK_COMM_LEN];
};
struct openat_args {
    const char *filename;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, struct openat_args);
} openat_enter_map SEC(".maps"); // track these PIDs

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_open(struct trace_event_raw_sys_enter* ctx)
{
    struct event evt = {};

    struct task_struct *task;
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    
    if (pid_filter && pid != pid_filter) {
        return 0;
    }
    task = (struct task_struct *)bpf_get_current_task();
    evt.pid = pid;
    struct openat_args args = {
        .filename = (const char *)ctx->args[1]  // second arg is filename
    };

    
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    int found = 0;
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (bpf_strcmp(evt.comm, GOLD[i]) == 0) {
            found = 1;
            break;
        }
    }
    
    if (!found) {
        return 0;
    }
    bpf_printk("SSHD FOUND ON PID: %d args: %s!!!", pid, ctx->args[1]);
    bpf_map_update_elem(&openat_enter_map, &pid, &args, BPF_ANY); // track it

    return 0;
}


SEC("tracepoint/syscalls/sys_enter_read")
int read_contents(struct trace_event_raw_sys_enter* ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&openat_enter_map, &pid)){
        bpf_printk("entered read!");
    }
    return 0;
}


