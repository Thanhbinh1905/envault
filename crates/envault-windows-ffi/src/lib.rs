//! Isolated Windows FFI primitives for EnVault's named-pipe transport.
//!
//! Every other crate in this workspace forbids `unsafe_code` outright, and
//! `forbid` cannot be locally overridden, so the one narrow exception this
//! crate exists for (a named-pipe security descriptor restricted to the
//! owning user, and comparing a connected peer's security identifier against
//! the current process) lives here instead, in a crate that opts out of the
//! workspace lint table and uses `deny` with a local `allow` per function
//! that needs it. See ADR 0013 for the full rationale. Every public function
//! is safe; no `unsafe` keyword appears outside this crate.

#![deny(unsafe_code)]
#![cfg(windows)]

use std::{
    ffi::OsStr,
    fs::File,
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, RawHandle},
    },
    ptr,
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, HANDLE, LocalFree},
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT,
            SetNamedSecurityInfoW,
        },
        DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorDacl, GetTokenInformation,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_NORMAL,
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, GetFileInformationByHandle,
        OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    },
    System::{
        Pipes::{
            CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
            PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
            PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        },
        RemoteDesktop::ProcessIdToSessionId,
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

/// Wide-string SDDL granting `GENERIC_ALL` to the object's owner only, with a
/// protected DACL (no inherited entries). The `OW` placeholder is resolved by
/// the OS to whichever security identifier ends up owning the created object,
/// so this crate never needs to look up or embed an explicit SID string.
const OWNER_ONLY_SDDL: &str = "D:P(A;;GA;;;OW)";

/// An owned Windows security descriptor plus the `SECURITY_ATTRIBUTES`
/// pointing at it, suitable for passing to `CreateNamedPipeW`. Freed via
/// `LocalFree` on drop.
pub struct OwnerOnlySecurityAttributes {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

impl OwnerOnlySecurityAttributes {
    fn as_ptr(&mut self) -> *mut SECURITY_ATTRIBUTES {
        &raw mut self.attributes
    }
}

impl Drop for OwnerOnlySecurityAttributes {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: `descriptor` was allocated by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW`, which
            // documents that the caller must free the returned buffer with
            // `LocalFree`. It is freed exactly once, here, and never used
            // again afterward because this is the destructor.
            unsafe {
                LocalFree(self.descriptor as _);
            }
        }
    }
}

/// Builds a security descriptor that grants full control only to the
/// creating object's owner, denying every other principal, including
/// `Everyone` and anonymous connections that Windows would otherwise grant
/// read access to by default on a named pipe.
#[allow(unsafe_code)]
pub fn owner_only_security_attributes() -> io::Result<OwnerOnlySecurityAttributes> {
    let sddl = to_wide(OWNER_ONLY_SDDL);
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `sddl` is a valid, NUL-terminated wide string that outlives
    // this call. `descriptor` is an out-parameter the API populates with a
    // freshly `LocalAlloc`-backed buffer on success, which
    // `OwnerOnlySecurityAttributes::drop` frees exactly once. We pass
    // `null_mut()` for the size out-parameter because we only need the
    // descriptor pointer, which the API permits.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    };
    if ok == 0 || descriptor.is_null() {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    Ok(OwnerOnlySecurityAttributes {
        descriptor,
        attributes,
    })
}

/// Restricts an already-existing file or directory's access control list to
/// its owner only, using the same owner-only descriptor
/// `owner_only_security_attributes` builds for creation time. Intended for
/// retrofitting a path that already exists (`envault-platform`'s private
/// file, directory, and socket-equivalent hardening calls this after
/// creation, mirroring the Unix `chmod 0600`/`0700` step).
#[allow(unsafe_code)]
pub fn restrict_path_to_owner(path: &std::path::Path) -> io::Result<()> {
    let wide_path = to_wide(&path.as_os_str().to_string_lossy());
    let security = owner_only_security_attributes()?;
    let mut dacl_present = 0;
    let mut dacl = ptr::null_mut();
    let mut dacl_defaulted = 0;
    // SAFETY: `security.descriptor` was populated by
    // `ConvertStringSecurityDescriptorToSecurityDescriptorW` inside
    // `owner_only_security_attributes` and is valid for the lifetime of
    // `security`, which outlives this call. `dacl_present`, `dacl`, and
    // `dacl_defaulted` are valid out-parameter locations; a non-zero
    // `dacl_present` on success means `dacl` now points inside the same
    // descriptor buffer, which stays alive until `security` drops after
    // `SetNamedSecurityInfoW` below has already copied what it needs.
    let ok = unsafe {
        GetSecurityDescriptorDacl(
            security.descriptor,
            &raw mut dacl_present,
            &raw mut dacl,
            &raw mut dacl_defaulted,
        )
    };
    if ok == 0 || dacl_present == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `wide_path` is a valid NUL-terminated wide string owned for
    // the duration of this call. `dacl` points inside `security`'s
    // descriptor buffer, which is still alive (it drops at the end of this
    // function, after this call returns). Every owner/group/SACL parameter
    // is null because only the DACL is being replaced.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr() as *mut _,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// Creates one instance of a byte-mode, duplex named pipe restricted to the
/// owning user via `owner_only_security_attributes`. Each returned instance
/// serves exactly one client connection; callers must create a new instance
/// after each client disconnects, mirroring how a Unix listener accepts one
/// connection per `accept()` call.
#[allow(unsafe_code)]
pub fn create_named_pipe_instance(path: &OsStr, first_instance: bool) -> io::Result<File> {
    let wide_path = to_wide(&path.to_string_lossy());
    let mut security = owner_only_security_attributes()?;
    let open_mode = PIPE_ACCESS_DUPLEX
        | FILE_FLAG_OVERLAPPED
        | if first_instance {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    // SAFETY: `wide_path` is a valid NUL-terminated wide string owned for
    // the duration of this call. `security.as_ptr()` points at a
    // `SECURITY_ATTRIBUTES` whose `lpSecurityDescriptor` remains valid until
    // `security` drops, which happens after this call returns. On success
    // the returned `HANDLE` is a uniquely owned pipe instance handle, wrapped
    // immediately into a `File` so normal `Drop`/`Read`/`Write` semantics
    // apply from here on; on failure `INVALID_HANDLE_VALUE` is never wrapped.
    let handle = unsafe {
        CreateNamedPipeW(
            wide_path.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            security.as_ptr(),
        )
    };
    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` was just returned by `CreateNamedPipeW` above as a
    // fresh, uniquely owned handle; wrapping it in `File` transfers
    // ownership so it is closed exactly once when the `File` drops.
    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

/// Creates one instance of an async, tokio-native named pipe server
/// restricted to the owning user, for use by the daemon's async accept loop.
/// Mirrors `create_named_pipe_instance`, but returns tokio's
/// [`tokio::net::windows::named_pipe::NamedPipeServer`] instead of a
/// blocking [`File`], since the daemon dispatches connections on a tokio
/// runtime rather than blocking threads.
#[allow(unsafe_code)]
pub fn create_named_pipe_server(
    name: &str,
    first_instance: bool,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    let mut security = owner_only_security_attributes()?;
    let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true);
    // SAFETY: `security` is a fully initialized `SECURITY_ATTRIBUTES` whose
    // `lpSecurityDescriptor` points at a live descriptor buffer for the
    // duration of this call; `security` is not dropped until after
    // `create_with_security_attributes_raw` returns, by which point the
    // pipe object has already been constructed from it. Tokio's documented
    // contract for this function is exactly that the pointer be valid for
    // the duration of the call, which this satisfies.
    unsafe {
        options
            .create_with_security_attributes_raw(name, security.as_ptr().cast::<std::ffi::c_void>())
    }
}

/// Returns the process ID of the client connected to `handle`, which must be
/// an open named-pipe server-side handle (e.g. from a tokio
/// `NamedPipeServer`'s `AsRawHandle`).
#[allow(unsafe_code)]
pub fn named_pipe_client_process_id(handle: std::os::windows::io::RawHandle) -> io::Result<u32> {
    let mut pid: u32 = 0;
    // SAFETY: the caller guarantees `handle` is a valid, open named-pipe
    // server handle for the duration of this call. `pid` is a valid
    // out-parameter location.
    let ok = unsafe { GetNamedPipeClientProcessId(handle as HANDLE, &raw mut pid) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

/// Returns `true` only if `pid` names a process owned by the same security
/// identifier as the current process. A thin, differently named entry point
/// onto the same check `verify_pipe_client_is_current_user` uses, for
/// callers that have already resolved a raw process ID (for example the
/// daemon's async accept loop, which reads the client PID directly off a
/// tokio `NamedPipeServer` handle rather than a blocking `File`).
pub fn is_current_user_pid(pid: u32) -> io::Result<bool> {
    verify_pid_is_current_user(pid)
}

/// Returns the Windows Terminal Services session ID that `pid` belongs to.
/// This is the Windows analog of the Unix login-session ID
/// (`getsid`/`setsid`): stable across every process a human starts within
/// one logon session, which is exactly the granularity the daemon's
/// per-session rate limiting and admin-lease binding needs, rather than a
/// per-process value that would change on every new CLI invocation.
#[allow(unsafe_code)]
pub fn named_pipe_client_session_id(pid: u32) -> io::Result<u32> {
    let mut session_id: u32 = 0;
    // SAFETY: `pid` is any `u32`; the API validates it internally and
    // reports failure through its return value, checked below. `session_id`
    // is a valid out-parameter location.
    let ok = unsafe { ProcessIdToSessionId(pid, &raw mut session_id) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(session_id)
}

/// Connects to an existing named pipe server as a client. Does not retry on
/// `ERROR_PIPE_BUSY`; the caller decides whether and how to retry.
#[allow(unsafe_code)]
pub fn connect_named_pipe_client(path: &OsStr) -> io::Result<File> {
    let wide_path = to_wide(&path.to_string_lossy());
    // SAFETY: `wide_path` is a valid NUL-terminated wide string owned for
    // the duration of this call. No security attributes are supplied
    // because the client does not need to set a descriptor on an existing
    // pipe object. On success the returned `HANDLE` is uniquely owned by
    // this call and wrapped immediately into a `File`.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) {
            return Err(error);
        }
        return Err(error);
    }
    // SAFETY: see above; `handle` is a fresh, uniquely owned handle.
    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

/// Returns `true` only if the process on the other end of `pipe`, identified
/// as the pipe's *client*, has the same owning security identifier as the
/// current process. Intended for the daemon side, which is the pipe server
/// and must authenticate the connecting client.
#[allow(unsafe_code)]
pub fn verify_pipe_client_is_current_user(pipe: &File) -> io::Result<bool> {
    let mut pid: u32 = 0;
    // SAFETY: `pipe.as_raw_handle()` is a valid, open named-pipe handle for
    // the lifetime of this call (borrowed from `pipe`, which outlives the
    // call). `pid` is a valid out-parameter location.
    let ok = unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &raw mut pid) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    verify_pid_is_current_user(pid)
}

/// Returns `true` only if the process on the other end of `pipe`, identified
/// as the pipe's *server*, has the same owning security identifier as the
/// current process. Intended for the client side, which connects to a named
/// pipe path it does not otherwise control and must authenticate the daemon
/// serving it before trusting anything it sends.
#[allow(unsafe_code)]
pub fn verify_pipe_server_is_current_user(pipe: &File) -> io::Result<bool> {
    let mut pid: u32 = 0;
    // SAFETY: same invariant as `verify_pipe_client_is_current_user`, using
    // the server-process query instead of the client-process query.
    let ok = unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as HANDLE, &raw mut pid) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    verify_pid_is_current_user(pid)
}

#[allow(unsafe_code)]
fn verify_pid_is_current_user(pid: u32) -> io::Result<bool> {
    // SAFETY: `GetCurrentProcessId` takes no arguments and cannot fail.
    if pid == unsafe { GetCurrentProcessId() } {
        return Ok(true);
    }
    let peer_sid = process_owner_sid(pid)?;
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that is always
    // valid and requires no `CloseHandle`.
    let current_process = unsafe { GetCurrentProcess() };
    let current_sid = token_owner_sid(current_process, false)?;
    // SAFETY: both `peer_sid` and `current_sid` are well-formed SID buffers
    // produced by `token_owner_sid`, which validates the `TOKEN_USER`
    // structure `GetTokenInformation` populated before returning them. Both
    // buffers outlive this call.
    let equal = unsafe { EqualSid(peer_sid.as_ptr() as *mut _, current_sid.as_ptr() as *mut _) };
    Ok(equal != 0)
}

#[allow(unsafe_code)]
fn process_owner_sid(pid: u32) -> io::Result<Vec<u8>> {
    // SAFETY: `pid` is caller-supplied but `OpenProcess` itself validates it;
    // a failure returns a null handle, checked immediately below, and no
    // handle is used before that check.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let result = token_owner_sid(process, true);
    // SAFETY: `process` was returned by the successful `OpenProcess` call
    // above and has not been closed yet; closing it here, exactly once,
    // releases the only handle this function opened.
    unsafe {
        CloseHandle(process);
    }
    result
}

#[allow(unsafe_code)]
fn token_owner_sid(process: HANDLE, close_token: bool) -> io::Result<Vec<u8>> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: `process` is a valid, open process handle for the duration of
    // this call (either the current pseudo-handle, which needs no closing,
    // or a handle this module just opened and owns). `token` is a valid
    // out-parameter location.
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = read_token_user_sid(token);
    if close_token {
        // SAFETY: `token` was returned by the successful `OpenProcessToken`
        // call above and has not been closed yet.
        unsafe {
            CloseHandle(token);
        }
    }
    result
}

#[allow(unsafe_code)]
fn read_token_user_sid(token: HANDLE) -> io::Result<Vec<u8>> {
    let mut needed: u32 = 0;
    // SAFETY: passing a zero-length buffer with `TokenUser` is the
    // documented way to ask `GetTokenInformation` how large a buffer is
    // needed; it writes that size into `needed` and returns an error we
    // deliberately ignore here, since failure with insufficient buffer size
    // is the expected outcome of this probing call.
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &raw mut needed);
    }
    if needed == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "GetTokenInformation did not report a required buffer size",
        ));
    }
    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: `buffer` is exactly `needed` bytes, matching the size the
    // probing call above reported, so `GetTokenInformation` will not write
    // past its end. `needed` is reused as an out-parameter for the actual
    // size written, which cannot exceed the buffer's own length here.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `buffer` was populated by the successful call above with a
    // valid `TOKEN_USER` at its start, whose `Sid` field points inside a
    // buffer of at least `needed` bytes; the returned `Vec` retains that
    // same buffer so the pointer relationship used by `EqualSid` callers
    // stays valid for as long as this `Vec` is alive.
    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    if token_user.User.Sid.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "token user SID pointer was null",
        ));
    }
    Ok(buffer)
}

/// Returns `(volume_serial_number, file_index)` for an open file or
/// directory handle: the stable identity pair Windows exposes for a
/// filesystem object, equivalent in role to the Unix `(dev, ino)` pair.
/// `std::os::windows::fs::MetadataExt::file_index`/`volume_serial_number`
/// expose the same data but remain behind the unstable `windows_by_handle`
/// feature on stable Rust, so this crate reads it directly via
/// `GetFileInformationByHandle` instead.
#[allow(unsafe_code)]
pub fn file_identity(file: &File) -> io::Result<(u64, u64)> {
    let mut info = BY_HANDLE_FILE_INFORMATION {
        dwFileAttributes: 0,
        ftCreationTime: windows_sys::Win32::Foundation::FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        ftLastAccessTime: windows_sys::Win32::Foundation::FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        ftLastWriteTime: windows_sys::Win32::Foundation::FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        dwVolumeSerialNumber: 0,
        nFileSizeHigh: 0,
        nFileSizeLow: 0,
        nNumberOfLinks: 0,
        nFileIndexHigh: 0,
        nFileIndexLow: 0,
    };
    // SAFETY: `file.as_raw_handle()` is a valid, open handle for the
    // lifetime of this call (borrowed from `file`, which outlives the
    // call). `info` is a valid, fully initialized out-parameter location
    // sized exactly to `BY_HANDLE_FILE_INFORMATION`.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &raw mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Ok((u64::from(info.dwVolumeSerialNumber), index))
}

fn to_wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_only_security_attributes_builds_and_frees_without_error() {
        let attributes = owner_only_security_attributes().expect("build security attributes");
        assert!(!attributes.descriptor.is_null());
    }

    #[test]
    #[allow(unsafe_code)]
    fn current_process_is_verified_as_its_own_owner() {
        // SAFETY: `GetCurrentProcessId` takes no arguments and cannot fail.
        let pid = unsafe { GetCurrentProcessId() };
        assert!(verify_pid_is_current_user(pid).expect("verify current pid"));
    }

    #[test]
    fn a_different_pid_can_be_compared_without_panicking() {
        // pid 4 is the Windows System process on every real Windows install;
        // this only asserts the comparison completes without panicking, not
        // a specific boolean outcome, since it depends on the caller's
        // privilege level in whatever environment the test runs.
        let _ = verify_pid_is_current_user(4);
    }
}
