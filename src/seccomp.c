/*
 * Droidspaces v5 — High-performance Container Runtime
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "droidspace.h"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>

/* ---------------------------------------------------------------------------
 * Minimal Seccomp Filter (Universal)
 * ---------------------------------------------------------------------------*/

/*
 * ds_seccomp_apply_minimal()
 *
 * Blocks direct host kernel takeover vectors (module loading, kexec).
 * Applied unconditionally to all kernels and all modes.
 */
int ds_seccomp_apply_minimal(int hw_access) {
  (void)hw_access;
  struct sock_filter filter[] = {
      /* Validate architecture */
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
#if defined(__aarch64__)
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
#elif defined(__x86_64__)
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#elif defined(__arm__)
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_ARM, 1, 0),
#elif defined(__i386__)
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_I386, 1, 0),
#endif
      BPF_STMT(BPF_RET | BPF_K,
               SECCOMP_RET_ALLOW), /* wrong arch - pass through */

      /* Load syscall number */
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

      /* Kernel module loading - injects arbitrary code into host kernel */
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_init_module, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_finit_module, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_delete_module, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

      /* kexec - replaces the running host kernel */
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kexec_load, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

#ifdef __NR_kexec_file_load
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kexec_file_load, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif

      /* unshare(CLONE_NEWUSER) - a new user namespace grants a full capability
       * set within it, enabling further kernel exploits.
       * Block the CLONE_NEWUSER flag only - systemd legitimately calls
       * unshare(CLONE_NEWNS | CLONE_NEWUTS | ...) and must not be affected.
       *
       * This is a kernel attack surface restriction and applies to ALL modes.
       *
       * Jump layout (4 instructions skipped by jf so nr stays in acc):
       *   jf=4 skips: LD args[0], JSET, RET EPERM, LD nr → lands at clone check
       *   JSET jf=1 skips: RET EPERM → lands at LD nr → falls to clone check */
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unshare, 0, 4),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
               offsetof(struct seccomp_data, args[0])),
      BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x10000000 /* CLONE_NEWUSER */, 0,
               1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
      /* Reload syscall nr - reached by both "unshare without CLONE_NEWUSER"
       * (JSET jf=1) and falls through to the clone check below */
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

      /* clone(CLONE_NEWUSER) - same attack via the clone() syscall path.
       *
       * Jump layout (3 instructions skipped by jf):
       *   jf=3 skips: LD args[0], JSET, RET EPERM → lands at ALLOW
       *   JSET jf=1 skips: RET EPERM → lands at ALLOW */
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 3),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
               offsetof(struct seccomp_data, args[0])),
      BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x10000000 /* CLONE_NEWUSER */, 0,
               1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

      /* Allow everything else */
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
    ds_warn("[SEC] Failed to apply minimal seccomp filter: %s",
            strerror(errno));
    return -1;
  }

  ds_log("[SEC] Minimal seccomp filter applied.");
  return 0;
}

/* ---------------------------------------------------------------------------
 * Android System Call Filtering
 * ---------------------------------------------------------------------------*/

/*
 * android_seccomp_setup()
 *
 * Returns ENOSYS for keyring syscalls on legacy Android kernels (< 5.x)
 * to avoid unnecessary kernel path traversal for missing subsystems.
 *
 * When block_nested_ns=1, additionally blocks creation of new user namespaces
 * inside the container (unshare/clone with CLONE_NEWUSER or namespace flags).
 * This is required on stock kernels like 4.14.113 (Galaxy S10) which have a
 * VFS deadlock bug triggered by systemd sandboxing (PrivateTmp, etc.) that
 * calls grab_super() while holding a namespace lock.
 *
 * Trade-off: --block-nested-namespaces nukes systemd sandboxing and also
 * prevents running Docker inside the container, but fixes the hard deadlock.
 */
int android_seccomp_setup(int is_systemd, int block_nested_ns) {
  int major = 0, minor = 0;
  if (get_kernel_version(&major, &minor) < 0)
    return -1;
  if (major >= 5)
    return 0;

  ds_log("Legacy kernel (%d.%d) detected: Applying Android compatibility "
         "shield...",
         major, minor);

  /* Namespace flags to filter on legacy kernels (only for systemd).
   * Covers CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWNET|
   *        CLONE_NEWPID|CLONE_NEWCGROUP|CLONE_NEWUSER */
  const uint32_t ns_mask = 0x7E020000;

  struct sock_filter filter_base[] = {
      /* [0] Load architecture */
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),

  /* [1] Validate architecture -- wrong arch: allow unconditionally */
#if defined(__aarch64__)
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
#elif defined(__x86_64__)
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#elif defined(__arm__)
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_ARM, 1, 0),
#elif defined(__i386__)
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_I386, 1, 0),
#endif
      /* Wrong arch -- allow */
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

      /* [2] Load syscall number */
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

      /* [3] Keyring syscalls -> ENOSYS (missing in Android) */
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_keyctl, 0, 1),
      BPF_STMT(BPF_RET | BPF_K,
               SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),

      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_add_key, 0, 1),
      BPF_STMT(BPF_RET | BPF_K,
               SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),

      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_request_key, 0, 1),
      BPF_STMT(BPF_RET | BPF_K,
               SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),
  };

  /* Namespace filter appended only when --block-nested-namespaces is active
   * AND we are running a systemd rootfs.
   *
   * [4] Conditional jump: if not systemd, jump over the 5 namespace
   *     instructions (jf=5). If systemd, fall through to check the syscall.
   *
   * [5] Check for unshare(). If it IS unshare, fall-through to flag check.
   *     Otherwise check clone().
   *
   * [6] Check for clone(). If it IS clone, fall-through to flag check.
   *     Otherwise jump past the block to ALLOW (jf=3).
   *
   * [7] Load first argument (flags).
   * [8] If any namespace flag set, fall through to EPERM; otherwise jump
   *     over it (jf=1).
   * [9] Return EPERM.
   * [10] Allow everything else. */
  struct sock_filter filter_ns[] = {
      BPF_JUMP(BPF_JMP | BPF_JA, (uint16_t)(is_systemd ? 0 : 5), 0, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unshare, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 3),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
               offsetof(struct seccomp_data, args[0])),
      BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, ns_mask, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
      /* Default: Allow */
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  struct sock_filter filter_allow[] = {
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  /* Assemble the filter dynamically based on block_nested_ns */
  struct sock_filter combined[64];
  unsigned int count = 0;

  unsigned int base_count = sizeof(filter_base) / sizeof(filter_base[0]);
  if (count + base_count > 64)
    return -1;
  memcpy(combined + count, filter_base, base_count * sizeof(filter_base[0]));
  count += base_count;

  if (block_nested_ns) {
    ds_log("[SEC] --block-nested-namespaces active: nuking systemd sandbox "
           "calls to fix VFS deadlock on legacy kernel %d.%d.",
           major, minor);
    unsigned int ns_count = sizeof(filter_ns) / sizeof(filter_ns[0]);
    if (count + ns_count > 64)
      return -1;
    memcpy(combined + count, filter_ns, ns_count * sizeof(filter_ns[0]));
    count += ns_count;
  } else {
    /* No namespace filtering: just append the ALLOW default */
    unsigned int allow_count = sizeof(filter_allow) / sizeof(filter_allow[0]);
    if (count + allow_count > 64)
      return -1;
    memcpy(combined + count, filter_allow,
           allow_count * sizeof(filter_allow[0]));
    count += allow_count;
  }

  struct sock_fprog prog = {
      .len = (unsigned short)count,
      .filter = combined,
  };

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
    ds_warn("Failed to apply Android Seccomp filter: %s", strerror(errno));
    return -1;
  }

  return 0;
}
