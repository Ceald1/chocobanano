/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#define MAGIC "ceald"

// references:
// https://github.com/pathtofile/bad-bpf/tree/main
// https://github.com/Esonhugh/sshd_backdoor/tree/Skyworship








































char LICENSE[] SEC("license") = "GPL";