// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::platform::linux::seccomp::Filter;
use crate::platform::unix::process::Process;
use crate::profile::{self, AddressPattern, OperationSupport, OperationSupportLevel, Profile};
use crate::sandbox::{ChildSandboxMethods, Command, SandboxMethods};

use std::io;
use libc::{c_int, c_void, size_t, ssize_t};

pub mod misc;
pub mod namespace;
pub mod seccomp;

#[allow(missing_copy_implementations)]
#[derive(Clone, Debug)]
pub struct Operation;

impl OperationSupport for profile::Operation {
    fn support(&self) -> OperationSupportLevel {
        match *self {
            profile::Operation::FileReadAll(_) |
            profile::Operation::NetworkOutbound(AddressPattern::All) |
            profile::Operation::CreateNewProcesses |
            profile::Operation::SystemInfoRead => {
                OperationSupportLevel::CanBeAllowed
            }
            profile::Operation::FileReadMetadata(_) |
            profile::Operation::NetworkOutbound(AddressPattern::Tcp(_)) |
            profile::Operation::NetworkOutbound(AddressPattern::LocalSocket(_)) => {
                OperationSupportLevel::CannotBeAllowedPrecisely
            }
            profile::Operation::PlatformSpecific(_) => OperationSupportLevel::NeverAllowed,
        }
    }
}

pub struct Sandbox {
    profile: Profile,
}

impl Sandbox {
    pub fn new(profile: Profile) -> Sandbox {
        Sandbox {
            profile: profile,
        }
    }

    #[cfg(dump_bpf_sockets)]
    fn dump_filter(&self) {
        let filter = Filter::new(&self.profile);
        filter.dump();
    }

    #[cfg(not(dump_bpf_sockets))]
    fn dump_filter(&self) {}
}

impl SandboxMethods for Sandbox {
    fn profile(&self) -> &Profile {
        &self.profile
    }

    fn start(&self, command: &mut Command) -> io::Result<Process> {
        self.dump_filter();
        namespace::start(&self.profile, command)
    }
}

pub struct ChildSandbox {
    profile: Profile,
}

impl ChildSandbox {
    pub fn new(profile: Profile) -> ChildSandbox {
        ChildSandbox {
            profile: profile,
        }
    }
}

fn gettid() -> libc::pid_t {
    unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t }
}

fn getpid() -> libc::pid_t {
    unsafe { libc::getpid() }
}

pub fn log_stderr(s: &str) {
    let s = format!("WARN:gaol::platform::linux:{}.{}: {}\n", getpid(), gettid(), s);
    unsafe {
        assert!(libc::write(2,
                            s.as_bytes().as_ptr() as *const u8 as *const c_void,
                            s.len() as size_t) == s.len() as ssize_t);
    }
}

impl ChildSandboxMethods for ChildSandbox {
    fn activate(&self) -> Result<(),c_int> {
        namespace::activate(&self.profile)?;
        misc::activate()?;
        Filter::new(&self.profile).activate()
    }
}

