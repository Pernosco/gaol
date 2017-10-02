// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! `seccomp-bpf` support on recent Linux kernels.
//!
//! This works in tandem with `namespace` in order to implement sandbox profiles. It is generally
//! the weaker of the two approaches, because BPF is limited, but it's useful for reducing kernel
//! attack surface area and implementing coarse-grained policies.

#![allow(non_upper_case_globals, unused_imports)]

use platform::linux::namespace::{CLONE_CHILD_CLEARTID, CLONE_FILES, CLONE_FS};
use platform::linux::namespace::{CLONE_PARENT_SETTID, CLONE_SETTLS, CLONE_SIGHAND, CLONE_SYSVSEM};
use platform::linux::namespace::{CLONE_THREAD, CLONE_VM, CLONE_VFORK};
use profile::{Operation, Profile};

use libc::{self, AF_INET, AF_INET6, AF_UNIX, AF_NETLINK};
use libc::{c_char, c_int, c_long, c_ulong, c_ushort, c_void};
use libc::{O_NONBLOCK, O_DIRECTORY, O_RDONLY, O_NOCTTY, O_CLOEXEC, FIONREAD, FIOCLEX};
use libc::{MADV_NORMAL, MADV_RANDOM, MADV_SEQUENTIAL, MADV_WILLNEED, MADV_DONTNEED};
use libc::SIGCHLD;
use std::ffi::CString;
use std::mem;

/// The architecture number for x86.
#[cfg(target_arch="x86")]
const ARCH_NR: u32 = AUDIT_ARCH_X86;
/// The architecture number for x86-64.
#[cfg(target_arch="x86_64")]
const ARCH_NR: u32 = AUDIT_ARCH_X86_64;
/// The architecture number for ARM.
#[cfg(target_arch="arm")]
const ARCH_NR: u32 = AUDIT_ARCH_ARM;
/// The architecture number for ARM 64-bit.
#[cfg(target_arch="aarch64")]
const ARCH_NR: u32 = AUDIT_ARCH_AARCH64;
#[cfg(target_arch="powerpc")]
const ARCH_NR: u32 = AUDIT_ARCH_PPC;
#[cfg(all(target_arch="powerpc64", target_endian="big"))]
const ARCH_NR: u32 = AUDIT_ARCH_PPC64;
#[cfg(all(target_arch="powerpc64", target_endian="little"))]
const ARCH_NR: u32 = AUDIT_ARCH_PPC64LE;

const SECCOMP_RET_KILL: u32 = 0;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const LD: u16 = 0x00;
const JMP: u16 = 0x05;
const RET: u16 = 0x06;

const W: u16 = 0;
const ABS: u16 = 0x20;

const JEQ: u16 = 0x10;
const JSET: u16 = 0x40;

const K: u16 = 0x00;

const SYSCALL_NR_OFFSET: u32 = 0;
const ARCH_NR_OFFSET: u32 = 4;
const ARG_0_OFFSET: u32 = 16;
const ARG_1_OFFSET: u32 = 24;
const ARG_2_OFFSET: u32 = 32;

const NETLINK_ROUTE: c_int = 0;

const ARCH_SET_GS: u32 = 0x1001;
const ARCH_SET_FS: u32 = 0x1002;
const ARCH_GET_FS: u32 = 0x1003;
const ARCH_GET_GS: u32 = 0x1004;

const EM_386: u32 = 3;
const EM_PPC: u32 = 20;
const EM_PPC64: u32 = 21;
const EM_ARM: u32 = 40;
const EM_X86_64: u32 = 62;
const EM_AARCH64: u32 = 183;

/// A flag set in the architecture number for all 64-bit architectures.
const __AUDIT_ARCH_64BIT: u32 = 0x8000_0000;
/// A flag set in the architecture number for all little-endian architectures.
const __AUDIT_ARCH_LE: u32 = 0x4000_0000;
/// The architecture number for x86.
const AUDIT_ARCH_X86: u32 = EM_386 | __AUDIT_ARCH_LE;
/// The architecture number for x86-64.
const AUDIT_ARCH_X86_64: u32 = EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE;
/// The architecture number for ARM.
const AUDIT_ARCH_ARM: u32 = EM_ARM | __AUDIT_ARCH_LE;
/// The architecture number for ARM 64-bit.
const AUDIT_ARCH_AARCH64: u32 = EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE;
/// The architecture number for ppc.
const AUDIT_ARCH_PPC: u32 = EM_PPC;
/// The architecture number for ppc64.
const AUDIT_ARCH_PPC64: u32 = EM_PPC64 | __AUDIT_ARCH_64BIT;
/// The architecture number for ppc64le.
const AUDIT_ARCH_PPC64LE: u32 = EM_PPC64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE;

const PR_SET_SECCOMP: c_int = 22;
const PR_SET_NO_NEW_PRIVS: c_int = 38;

const SECCOMP_MODE_FILTER: c_ulong = 2;

static FILTER_PROLOGUE: [sock_filter; 3] = [
    VALIDATE_ARCHITECTURE_0,
    VALIDATE_ARCHITECTURE_1,
    VALIDATE_ARCHITECTURE_2,
];

// A most untimely end...
static FILTER_EPILOGUE: [sock_filter; 1] = [
    KILL_PROCESS,
];

/// Syscalls that are always allowed.
pub static ALLOWED_SYSCALLS: [c_long; 30] = [
    libc::SYS_brk,
    libc::SYS_close,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_futex,
    libc::SYS_getrandom,
    libc::SYS_getrlimit,
    libc::SYS_getrusage,
    libc::SYS_gettimeofday,
    libc::SYS_getuid,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_poll,
    libc::SYS_prlimit64,
    libc::SYS_read,
    libc::SYS_recvfrom,
    libc::SYS_recvmsg,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sched_getaffinity,
    libc::SYS_sendmmsg,
    libc::SYS_sendto,
    libc::SYS_set_robust_list,
    libc::SYS_set_tid_address,
    libc::SYS_setrlimit,
    libc::SYS_sigaltstack,
    libc::SYS_time,
    libc::SYS_write,
];

static ALLOWED_SYSCALLS_FOR_FILE_READ: [c_long; 9] = [
    libc::SYS_access,
    libc::SYS_fstat,
    libc::SYS_getdents,
    libc::SYS_getdents64,
    libc::SYS_lseek,
    libc::SYS_lstat,
    libc::SYS_readlink,
    libc::SYS_stat,
    libc::SYS_statfs,
];

static ALLOWED_SYSCALLS_FOR_NETWORK_OUTBOUND: [c_long; 3] = [
    libc::SYS_bind,
    libc::SYS_connect,
    libc::SYS_getsockname,
];

static ALLOWED_SYSCALLS_FOR_PROCESS_CREATION: [c_long; 4] = [
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_execve,
    libc::SYS_execveat,
];

const ALLOW_SYSCALL: sock_filter = sock_filter {
    code: RET + K,
    k: SECCOMP_RET_ALLOW,
    jt: 0,
    jf: 0,
};

const KILL_PROCESS: sock_filter = sock_filter {
    code: RET + K,
    k: SECCOMP_RET_KILL,
    jt: 0,
    jf: 0,
};

const EXAMINE_SYSCALL: sock_filter = sock_filter {
    code: LD + W + ABS,
    k: SYSCALL_NR_OFFSET,
    jt: 0,
    jf: 0,
};

const EXAMINE_ARG_0: sock_filter = sock_filter {
    code: LD + W + ABS,
    k: ARG_0_OFFSET,
    jt: 0,
    jf: 0,
};

const EXAMINE_ARG_1: sock_filter = sock_filter {
    code: LD + W + ABS,
    k: ARG_1_OFFSET,
    jt: 0,
    jf: 0,
};

const EXAMINE_ARG_2: sock_filter = sock_filter {
    code: LD + W + ABS,
    k: ARG_2_OFFSET,
    jt: 0,
    jf: 0,
};

const VALIDATE_ARCHITECTURE_0: sock_filter = sock_filter {
    code: LD + W + ABS,
    k: ARCH_NR_OFFSET,
    jt: 0,
    jf: 0,
};

const VALIDATE_ARCHITECTURE_1: sock_filter = sock_filter {
    code: JMP + JEQ + K,
    k: ARCH_NR,
    jt: 1,
    jf: 0,
};

const VALIDATE_ARCHITECTURE_2: sock_filter = KILL_PROCESS;

pub struct Filter {
    program: Vec<sock_filter>,
}

impl Filter {
    pub fn new(profile: &Profile) -> Filter {
        let mut filter = Filter {
            program: FILTER_PROLOGUE.iter().map(|x| *x).collect(),
        };
        filter.allow_syscalls(&ALLOWED_SYSCALLS);

        // glibc uses these during startup
        filter.if_syscall_is(libc::SYS_arch_prctl, |filter| {
            filter.if_arg0_is(ARCH_SET_GS as u32, |filter| filter.allow_this_syscall());
            filter.if_arg0_is(ARCH_SET_FS as u32, |filter| filter.allow_this_syscall());
            filter.if_arg0_is(ARCH_GET_FS as u32, |filter| filter.allow_this_syscall());
            filter.if_arg0_is(ARCH_GET_GS as u32, |filter| filter.allow_this_syscall());
        });

        if profile.allowed_operations().iter().any(|operation| {
            match *operation {
                Operation::FileReadAll(_) | Operation::FileReadMetadata(_) => true,
                _ => false,
            }
        }) {
            filter.allow_syscalls(&ALLOWED_SYSCALLS_FOR_FILE_READ);

            // Only allow file reading.
            filter.if_syscall_is(libc::SYS_open, |filter| {
                filter.if_arg1_hasnt_set(!(O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK) as u32,
                                         |filter| filter.allow_this_syscall())
            });

            // Only allow the `FIONREAD` or `FIOCLEX` `ioctl`s to be performed.
            filter.if_syscall_is(libc::SYS_ioctl, |filter| {
                filter.if_arg1_is(FIONREAD as u32, |filter| filter.allow_this_syscall());
                filter.if_arg1_is(FIOCLEX as u32, |filter| filter.allow_this_syscall())
            })
        }

        if profile.allowed_operations().iter().any(|operation| {
            match *operation {
                Operation::NetworkOutbound(_) => true,
                _ => false,
            }
        }) {
            filter.allow_syscalls(&ALLOWED_SYSCALLS_FOR_NETWORK_OUTBOUND);

            // Only allow Unix, IPv4, IPv6, and netlink route sockets to be created.
            filter.if_syscall_is(libc::SYS_socket, |filter| {
                filter.if_arg0_is(AF_UNIX as u32, |filter| filter.allow_this_syscall());
                filter.if_arg0_is(AF_INET as u32, |filter| filter.allow_this_syscall());
                filter.if_arg0_is(AF_INET6 as u32, |filter| filter.allow_this_syscall());
                filter.if_arg0_is(AF_NETLINK as u32, |filter| {
                    filter.if_arg2_is(NETLINK_ROUTE as u32, |filter| filter.allow_this_syscall())
                })
            })
        }

        let allow_process_creation = profile.allowed_operations().iter().any(|operation| {
            match *operation {
                Operation::CreateNewProcesses => true,
                _ => false,
            }
        });
        if allow_process_creation {
            filter.allow_syscalls(&ALLOWED_SYSCALLS_FOR_PROCESS_CREATION);
        }

        // Only allow normal threads to be created, or vfork/fork if they
        // are enabled.
        filter.if_syscall_is(libc::SYS_clone, |filter| {
            filter.if_arg0_is((CLONE_VM |
                               CLONE_FS |
                               CLONE_FILES |
                               CLONE_SIGHAND |
                               CLONE_THREAD |
                               CLONE_SYSVSEM |
                               CLONE_SETTLS |
                               CLONE_PARENT_SETTID |
                               CLONE_CHILD_CLEARTID) as u32,
                              |filter| filter.allow_this_syscall());
            if allow_process_creation {
                filter.if_arg0_is(SIGCHLD as u32,
                                  |filter| filter.allow_this_syscall());
                filter.if_arg0_is((CLONE_VM |
                                   CLONE_VFORK |
                                   SIGCHLD) as u32,
                                  |filter| filter.allow_this_syscall());
            }
        });

        // Only allow the POSIX values for `madvise`.
        filter.if_syscall_is(libc::SYS_madvise, |filter| {
            for mode in [
                MADV_NORMAL,
                MADV_RANDOM,
                MADV_SEQUENTIAL,
                MADV_WILLNEED,
                MADV_DONTNEED
            ].iter() {
                filter.if_arg2_is(*mode as u32, |filter| filter.allow_this_syscall())
            }
        });

        filter.program.extend_from_slice(&FILTER_EPILOGUE);
        filter
    }

    /// Dumps this filter to a temporary file.
    #[cfg(dump_bpf_sockets)]
    pub fn dump(&self) {
        let path = CString::from_slice(b"/tmp/gaol-bpf.XXXXXX");
        let mut path = path.as_bytes_with_nul().to_vec();
        let fd = unsafe {
            mkstemp(path.as_mut_ptr() as *mut c_char)
        };
        let nbytes = self.program.len() * mem::size_of::<sock_filter>();
        unsafe {
            assert!(libc::write(fd, self.program.as_ptr() as *const c_void, nbytes as u64) ==
                    nbytes as i64);
            libc::close(fd);
        }
    }

    #[cfg(not(dump_bpf_sockets))]
    pub fn dump(&self) {}

    /// Activates this filter, applying all of its restrictions forevermore. This can only be done
    /// once.
    pub fn activate(&self) -> Result<(),c_int> {
        unsafe {
            let result = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if result != 0 {
                return Err(result)
            }

            let program = sock_fprog {
                len: self.program.len() as c_ushort,
                filter: self.program.as_ptr(),
            };
            let result = prctl(PR_SET_SECCOMP,
                               SECCOMP_MODE_FILTER,
                               &program as *const sock_fprog as usize as c_ulong,
                               !0,
                               0);
            if result == 0 {
                Ok(())
            } else {
                Err(result)
            }
        }
    }

    fn allow_this_syscall(&mut self) {
        self.program.push(ALLOW_SYSCALL)
    }

    fn allow_syscalls(&mut self, syscalls: &[c_long]) {
        for &syscall in syscalls.iter() {
            self.if_syscall_is(syscall, |filter| filter.allow_this_syscall())
        }
    }

    fn if_syscall_is<F>(&mut self, number: c_long, then: F) where F: FnMut(&mut Filter) {
        self.program.push(EXAMINE_SYSCALL);
        self.if_k_is(number as u32, then)
    }

    fn if_arg0_is<F>(&mut self, value: u32, then: F) where F: FnMut(&mut Filter) {
        self.program.push(EXAMINE_ARG_0);
        self.if_k_is(value, then)
    }

    fn if_arg1_is<F>(&mut self, value: u32, then: F) where F: FnMut(&mut Filter) {
        self.program.push(EXAMINE_ARG_1);
        self.if_k_is(value, then)
    }

    fn if_arg1_hasnt_set<F>(&mut self, value: u32, then: F) where F: FnMut(&mut Filter) {
        self.program.push(EXAMINE_ARG_1);
        self.if_k_hasnt_set(value, then)
    }

    fn if_arg2_is<F>(&mut self, value: u32, then: F) where F: FnMut(&mut Filter) {
        self.program.push(EXAMINE_ARG_2);
        self.if_k_is(value, then)
    }

    fn if_k_is<F>(&mut self, value: u32, mut then: F) where F: FnMut(&mut Filter) {
        let index = self.program.len();
        self.program.push(sock_filter {
            code: JMP + JEQ + K,
            k: value,
            jt: 0,
            jf: 0,
        });
        then(self);
        self.program[index].jf = (self.program.len() - index - 1) as u8;
    }

    fn if_k_hasnt_set<F>(&mut self, value: u32, mut then: F) where F: FnMut(&mut Filter) {
        let index = self.program.len();
        self.program.push(sock_filter {
            code: JMP + JSET + K,
            k: value,
            jt: 0,
            jf: 0,
        });
        then(self);
        self.program[index].jt = (self.program.len() - index - 1) as u8;
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct sock_filter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct sock_fprog {
    len: c_ushort,
    filter: *const sock_filter,
}

#[allow(dead_code)]
extern {
    fn mkstemp(template: *mut c_char) -> c_int;
    pub fn prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong)
                 -> c_int;
}

