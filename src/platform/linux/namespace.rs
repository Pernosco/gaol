// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Sandboxing on Linux via namespaces.

use crate::platform::linux::seccomp;
use crate::platform::unix::process::Process;
use crate::platform::unix;
use crate::profile::{Operation, PathPattern, Profile};
use crate::sandbox::Command;

use libc::{self, EINVAL, O_CLOEXEC, c_char, c_int, c_ulong, c_void, gid_t, pid_t, size_t, ssize_t, uid_t};
use log::warn;
use std::env;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Write};
use std::iter;
use std::mem;
use std::os::unix::io::RawFd;
use std::os::unix::prelude::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

/// Creates a namespace and sets up a chroot jail.
pub fn activate(profile: &Profile) -> Result<(),c_int> {
    let jail = ChrootJail::new(profile)?;
    jail.enter()?;
    drop_capabilities()
}

/// A `chroot` jail with a restricted view of the filesystem inside it.
struct ChrootJail {
    directory: PathBuf,
}

impl ChrootJail {
    /// Creates a new `chroot` jail.
    fn new(profile: &Profile) -> Result<ChrootJail,c_int> {
        let prefix = CString::new("/tmp/gaol.XXXXXX").unwrap();
        let mut prefix: Vec<u8> = prefix.as_bytes_with_nul().iter().map(|x| *x).collect();
        unsafe {
            if mkdtemp(prefix.as_mut_ptr() as *mut c_char).is_null() {
                return Err(-1)
            }
        }
        let jail_dir = PathBuf::from(OsStr::from_bytes(&prefix[..prefix.len() - 1]));
        let jail = ChrootJail {
            directory: jail_dir,
        };

        let dest = CString::new(jail.directory
                                    .as_os_str()
                                    .to_str()
                                    .unwrap()
                                    .as_bytes()).unwrap();
        let tmpfs = CString::new("tmpfs").unwrap();
        let result = unsafe {
            mount(tmpfs.as_ptr(),
                  dest.as_ptr(),
                  tmpfs.as_ptr(),
                  MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID,
                  ptr::null())
        };
        if result != 0 {
            return Err(result)
        }

        for operation in profile.allowed_operations().iter() {
            if let Operation::FileReadAll(ref pattern) = *operation {
                match *pattern {
                    PathPattern::Literal(ref path) |
                    PathPattern::Subpath(ref path) => {
                        jail.bind_mount(path, path)?;
                    }
                    PathPattern::LiteralAlias(ref dst, ref src) |
                    PathPattern::SubpathAlias(ref dst, ref src) => {
                        jail.bind_mount(dst, src)?;
                    }
                }
            }
        }

        Ok(jail)
    }

    /// Enters the `chroot` jail.
    fn enter(&self) -> Result<(),c_int> {
        let directory = CString::new(self.directory
                                         .as_os_str()
                                         .to_str()
                                         .unwrap()
                                         .as_bytes()).unwrap();
        let result = unsafe {
            chroot(directory.as_ptr())
        };
        if result != 0 {
            return Err(result)
        }

        match env::set_current_dir("/") {
            Ok(_) => Ok(()),
            Err(_) => Err(-1),
        }
    }

    /// Bind mounts a path into our chroot jail.
    fn bind_mount(&self, dest_path: &Path, source_path: &Path) -> Result<(),c_int> {
        // Create all intermediate directories.
        let mut jail_path = self.directory.clone();
        let mut components: Vec<OsString> =
            dest_path.components().skip(1)
                                    .map(|component| component.as_os_str().to_os_string())
                                    .collect();
        let last_component = components.pop();
        for component in components.into_iter() {
            jail_path.push(component);
            if let Err(e) = fs::create_dir(&jail_path) {
                if e.kind() != io::ErrorKind::AlreadyExists {
                    return Err(-1)
                }
            }
        }

        // Create the mount file or directory.
        if let Some(last_component) = last_component {
            jail_path.push(last_component);
            match fs::metadata(source_path) {
                Ok(ref metadata) if metadata.is_dir() => {
                    if fs::create_dir(&jail_path).is_err() {
                        return Err(-1)
                    }
                }
                Ok(_) => {
                    if File::create(&jail_path).is_err() {
                        return Err(-1)
                    }
                }
                Err(_) => {
                    // The source directory didn't exist. Just don't create the bind mount.
                    // Don't log anything here; it's not safe to use logging in a forked
                    // but not execed process, since the logging lock could have been held
                    // at the time of the fork.
                    return Ok(())
                }
            }
        }

        // Create the bind mount.
        let source_path = CString::new(source_path.as_os_str()
                                                  .to_str()
                                                  .unwrap()
                                                  .as_bytes()).unwrap();
        let jail_path = CString::new(jail_path.as_os_str()
                                              .to_str()
                                              .unwrap()
                                              .as_bytes()).unwrap();
        let bind = CString::new("bind").unwrap();
        // Readonly directories and files are mounted readonly as an
        // extra layer of security; currently we deny opening writeable files using
        // the seccomp filter, but that could change or have a bug.
        let result = unsafe {
            mount(source_path.as_ptr(),
                  jail_path.as_ptr(),
                  bind.as_ptr(),
                  MS_MGC_VAL | MS_BIND | MS_REC | libc::MS_RDONLY,
                  ptr::null_mut())
        };
        if result == 0 {
            Ok(())
        } else {
            Err(result)
        }
    }
}

/// Removes fake-superuser capabilities. This removes our ability to mess with the filesystem view
/// we've set up.
fn drop_capabilities() -> Result<(),c_int> {
    let capability_data: Vec<_> = iter::repeat(__user_cap_data_struct {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }).take(_LINUX_CAPABILITY_U32S_3 as usize).collect();
    let result = unsafe {
        capset(&__user_cap_header_struct {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        }, capability_data.as_ptr())
    };
    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}

/// Sets up the user and PID namespaces.
unsafe fn prepare_user_and_pid_namespaces(parent_uid: uid_t, parent_gid: gid_t) -> io::Result<()> {
    // Enter the main user and PID namespaces.
    assert!(unshare(CLONE_NEWUSER | CLONE_NEWPID) == 0);

    // See http://crbug.com/457362 for more information on this.
    File::create(&Path::new("/proc/self/setgroups"))?.write_all(b"deny")?;

    let gid_contents = format!("0 {} 1", parent_gid);
    File::create(&Path::new("/proc/self/gid_map"))?.write_all(gid_contents.as_bytes())?;
    let uid_contents = format!("0 {} 1", parent_uid);
    File::create(&Path::new("/proc/self/uid_map"))?.write_all(uid_contents.as_bytes())?;
    Ok(())
}

unsafe fn fork_wrapper() -> io::Result<pid_t> {
    let child = fork();
    if child >= 0 {
        Ok(child)
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe fn pipe_write(pipe: RawFd, value: i32) {
    assert!(libc::write(pipe,
                        &value as *const i32 as *const c_void,
                        mem::size_of::<i32>() as size_t) == mem::size_of::<i32>() as ssize_t);
}

unsafe fn pipe_write_str(pipe: RawFd, s: &str) {
    assert!(libc::write(pipe,
                        &s.len() as *const usize as *const c_void,
                        mem::size_of::<usize>() as size_t) == mem::size_of::<size_t>() as ssize_t);
    assert!(libc::write(pipe,
                        s.as_bytes().as_ptr() as *const u8 as *const c_void,
                        s.len() as size_t) == s.len() as ssize_t);
}

unsafe fn pipe_read(pipe: RawFd) -> io::Result<Option<i32>> {
    let mut v: i32 = 0;
    let bytes = libc::read(pipe,
                           &mut v as *mut i32 as *mut c_void,
                           mem::size_of::<i32>() as size_t);
    if bytes == mem::size_of::<i32>() as ssize_t {
        Ok(Some(v))
    } else if bytes == 0 {
        Ok(None)
    } else if bytes > 0 {
        panic!("No idea how we got a partial read in this pipe");
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe fn pipe_read_str(pipe: RawFd) -> io::Result<String> {
    let mut v: usize = 0;
    let bytes = libc::read(pipe,
                           &mut v as *mut usize as *mut c_void,
                           mem::size_of::<usize>() as size_t);
    if bytes == mem::size_of::<usize>() as ssize_t {
        // Do nothing
    } else if bytes >= 0 {
        panic!("No idea how we got a partial read in this pipe");
    } else {
        return Err(io::Error::last_os_error());
    }

    let mut buf = Vec::new();
    buf.resize(v, 0);
    let bytes = libc::read(pipe,
                           buf[..].as_mut_ptr() as *mut u8 as *mut c_void,
                           v as size_t);
    if bytes == v as ssize_t {
        // Do nothing
    } else if bytes >= 0 {
        panic!("No idea how we got a partial read in this pipe");
    } else {
        return Err(io::Error::last_os_error());
    }

    Ok(String::from_utf8(buf).unwrap())
}

enum PipeEntry {
    Pid(i32),
    Err(i32, String),
}

unsafe fn pipe_read_all(pipe: RawFd) -> io::Result<Vec<PipeEntry>> {
    let mut ret = Vec::new();
    while let Some(v) = pipe_read(pipe)? {
        if v > 0 {
            ret.push(PipeEntry::Pid(v));
        } else {
            ret.push(PipeEntry::Err(v, pipe_read_str(pipe)?));
        }
    }
    Ok(ret)
}

unsafe fn handle_error<T>(result: io::Result<T>, pipe: RawFd, context: &str) -> T {
    match result {
        Ok(v) => v,
        Err(e) => {
            pipe_write(pipe, -e.raw_os_error().unwrap_or(EINVAL));
            pipe_write_str(pipe, context);
            libc::exit(0);
        }
    }
}

/// Make all soft limits hard limits so the sandboxed child cannot increase them.
fn harden_limits() -> io::Result<()> {
    for resource in 0..libc::RLIMIT_NLIMITS {
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if unsafe { libc::getrlimit(resource, &mut limit as *mut libc::rlimit) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if limit.rlim_cur != libc::RLIM_INFINITY && limit.rlim_max != limit.rlim_cur {
            limit.rlim_max = limit.rlim_cur;
            if unsafe { libc::setrlimit(resource, &limit as *const libc::rlimit) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Spawns a child process in a new namespace.
///
/// This function is quite tricky. Hic sunt dracones!
pub fn start(profile: &Profile, command: &mut Command) -> io::Result<Process> {
    // Store our root namespace UID and GID because they're going to change once we enter a user
    // namespace.
    let (parent_uid, parent_gid) = unsafe {
        (libc::getuid(), libc::getgid())
    };

    // Always create an IPC namespace, a mount namespace, and a UTS namespace. Additionally, if we
    // aren't allowing network operations, create a network namespace.
    let mut unshare_flags = CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUTS;
    if !profile.allowed_operations().iter().any(|operation| {
        match *operation {
            Operation::NetworkOutbound(_) => true,
            _ => false,
        }
    }) {
        unshare_flags |= CLONE_NEWNET
    }

    unsafe {
        // Create a pipe so we can communicate the PID of our grandchild back.
        let mut pipe_fds = [0, 0];
        if libc::pipe2(&mut pipe_fds[0], O_CLOEXEC) != 0 {
            warn!("Pipe creation failed: {}", io::Error::last_os_error());
            return Err(io::Error::last_os_error());
        }

        // Set this `prctl` flag so that we can wait on our grandchild. (Otherwise it'll be
        // reparented to init.)
        assert!(seccomp::prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0);

        // Fork so that we can unshare without removing our ability to create threads.
        let forked = match fork_wrapper() {
            Ok(pid) => pid,
            Err(e) => {
                libc::close(pipe_fds[0]);
                libc::close(pipe_fds[1]);
                return Err(e);
            }
        };
        if forked == 0 {
            handle_error(harden_limits(), pipe_fds[1], "harden_limits");

            handle_error(command.inner.before_sandbox(&[pipe_fds[1]]), pipe_fds[1], "before_sandbox");
            // Set up our user and PID namespaces. The PID namespace won't actually come into
            // effect until the next fork(), because PIDs are immutable.
            handle_error(prepare_user_and_pid_namespaces(parent_uid, parent_gid), pipe_fds[1], "prepare_user_and_pid_namespaces");

            // Fork again, to enter the PID namespace.
            match handle_error(fork_wrapper(), pipe_fds[1], "inner fork") {
                0 => {
                    // Enter the auxiliary namespaces.
                    if unshare(unshare_flags) != 0 {
                        handle_error::<()>(Err(io::Error::last_os_error()), pipe_fds[1], "unshare");
                    }

                    handle_error(command.inner.before_exec(&[pipe_fds[1]]), pipe_fds[1], "before_exec");
                    // Go ahead and start the command.
                    handle_error::<()>(Err(unix::process::exec(command)), pipe_fds[1], "exec");
                }
                grandchild_pid => {
                    // Send the PID of our child up to our parent and exit.
                    pipe_write(pipe_fds[1], grandchild_pid);
                    libc::exit(0);
                }
            }
        }

        // Grandparent execution continues here.

        // Reap child zombie.
        waitpid(forked, ptr::null_mut(), 0);

        // Close pipe writer end now so that when the child/grandchild close
        // theirs, we'll get EOF on reading.
        libc::close(pipe_fds[1]);

        // Retrieve our grandchild's PID.
        let pipe_vals = pipe_read_all(pipe_fds[0]);
        libc::close(pipe_fds[0]);
        let pipe_vals = pipe_vals?;

        // We could get a PID followed by an error from the grandchild.
        let mut grandchild_pid = None;
        for e in pipe_vals {
            match e {
                PipeEntry::Pid(pid) => grandchild_pid = Some(pid),
                PipeEntry::Err(v, context) => {
                    if let Some(pid) = grandchild_pid {
                        // Reap failed grandchild zombie.
                        waitpid(pid, ptr::null_mut(), 0);
                    }
                    let err = io::Error::from_raw_os_error(-v);
                    warn!("Failed to start grandchild in {}: {}", context, err);
                    return Err(err);
                }
            }
        }

        Ok(Process {
            pid: grandchild_pid.expect("We should have something in the pipe"),
        })
    }
}

pub const CLONE_VM: c_int = 0x0000_0100;
pub const CLONE_FS: c_int = 0x0000_0200;
pub const CLONE_FILES: c_int = 0x0000_0400;
pub const CLONE_SIGHAND: c_int = 0x0000_0800;
pub const CLONE_VFORK: c_int = 0x0000_4000;
pub const CLONE_THREAD: c_int = 0x0001_0000;
pub const CLONE_NEWNS: c_int = 0x0002_0000;
pub const CLONE_SYSVSEM: c_int = 0x0004_0000;
pub const CLONE_SETTLS: c_int = 0x0008_0000;
pub const CLONE_PARENT_SETTID: c_int = 0x0010_0000;
pub const CLONE_CHILD_CLEARTID: c_int = 0x0020_0000;
pub const CLONE_NEWUTS: c_int = 0x0400_0000;
pub const CLONE_NEWIPC: c_int = 0x0800_0000;
pub const CLONE_NEWUSER: c_int = 0x1000_0000;
pub const CLONE_NEWPID: c_int = 0x2000_0000;
pub const CLONE_NEWNET: c_int = 0x4000_0000;

const MS_NOSUID: c_ulong = 2;
const MS_NODEV: c_ulong = 4;
const MS_NOEXEC: c_ulong = 8;
const MS_NOATIME: c_ulong = 1024;
const MS_BIND: c_ulong = 4096;
const MS_REC: c_ulong = 16384;
const MS_MGC_VAL: c_ulong = 0xc0ed_0000;

#[repr(C)]
#[allow(non_camel_case_types)]
struct __user_cap_header_struct {
    version: u32,
    pid: c_int,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
struct __user_cap_data_struct {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[allow(non_camel_case_types)]
type cap_user_header_t = *const __user_cap_header_struct;

#[allow(non_camel_case_types)]
type const_cap_user_data_t = *const __user_cap_data_struct;

const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const _LINUX_CAPABILITY_U32S_3: u32 = 2;

const PR_SET_CHILD_SUBREAPER: c_int = 36;

extern {
    fn capset(hdrp: cap_user_header_t, datap: const_cap_user_data_t) -> c_int;
    fn chroot(path: *const c_char) -> c_int;
    fn fork() -> pid_t;
    fn mkdtemp(template: *mut c_char) -> *mut c_char;
    fn mount(source: *const c_char,
             target: *const c_char,
             filesystemtype: *const c_char,
             mountflags: c_ulong,
             data: *const c_void)
             -> c_int;
    fn waitpid(pid: pid_t, stat_loc: *mut c_int, options: c_int) -> pid_t;
    fn unshare(flags: c_int) -> c_int;
}

