#![forbid(unsafe_code)]

use std::{env, fs, io, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("no user data directory is available")]
    MissingDataDirectory,
    #[error("filesystem operation failed")]
    Io(#[from] io::Error),
}

pub fn data_directory() -> Result<PathBuf, PlatformError> {
    if let Some(path) = env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(path).join("envault"));
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .map(|path| path.join(".local/share/envault"))
        .ok_or(PlatformError::MissingDataDirectory)
}

pub fn runtime_directory() -> Result<PathBuf, PlatformError> {
    if let Some(path) = env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(path).join("envault"));
    }
    Ok(data_directory()?.join("run"))
}

#[cfg(unix)]
pub fn harden_sensitive_process() -> Result<(), PlatformError> {
    use nix::sys::resource::{Resource, setrlimit};

    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(nix_error)?;
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_dumpable(false).map_err(nix_error)?;
    Ok(())
}

#[cfg(not(unix))]
pub fn harden_sensitive_process() -> Result<(), PlatformError> {
    Ok(())
}

#[cfg(unix)]
fn nix_error(error: nix::errno::Errno) -> PlatformError {
    PlatformError::Io(io::Error::from_raw_os_error(error as i32))
}

#[cfg(unix)]
pub fn create_private_directory(path: &std::path::Path) -> Result<(), PlatformError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fs::create_dir_all(path)?;
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_dir() || before.file_type().is_symlink() {
        return Err(invalid_private_path());
    }
    set_mode_no_follow(path, PrivateMode::Directory)?;
    let after = fs::symlink_metadata(path)?;
    if !after.file_type().is_dir()
        || after.file_type().is_symlink()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || after.permissions().mode() & 0o777 != 0o700
    {
        return Err(invalid_private_path());
    }
    Ok(())
}

#[cfg(unix)]
pub fn set_private_file_permissions(path: &std::path::Path) -> Result<(), PlatformError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || before.nlink() != 1 {
        return Err(invalid_private_path());
    }
    set_mode_no_follow(path, PrivateMode::File)?;
    let after = fs::symlink_metadata(path)?;
    if after.file_type().is_symlink()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || after.permissions().mode() & 0o777 != 0o600
    {
        return Err(invalid_private_path());
    }
    Ok(())
}

#[cfg(unix)]
pub fn create_private_file(path: &std::path::Path) -> Result<fs::File, PlatformError> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(PlatformError::from)?;
    validate_private_regular_file(&file, true)?;
    Ok(file)
}

#[cfg(unix)]
pub fn open_private_lock_file(path: &std::path::Path) -> Result<fs::File, PlatformError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)?;
    validate_private_regular_file(&file, false)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    validate_private_regular_file(&file, true)?;
    Ok(file)
}

#[cfg(unix)]
fn validate_private_regular_file(
    file: &fs::File,
    require_private_mode: bool,
) -> Result<(), PlatformError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || (require_private_mode && metadata.permissions().mode() & 0o777 != 0o600)
    {
        return Err(invalid_private_path());
    }
    Ok(())
}

#[cfg(unix)]
fn invalid_private_path() -> PlatformError {
    PlatformError::Io(io::Error::new(
        io::ErrorKind::InvalidInput,
        "private runtime path is not a stable private filesystem object",
    ))
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum PrivateMode {
    Directory,
    File,
}

#[cfg(unix)]
fn set_mode_no_follow(
    path: &std::path::Path,
    private_mode: PrivateMode,
) -> Result<(), PlatformError> {
    use nix::{
        fcntl::AT_FDCWD,
        sys::stat::{FchmodatFlags, Mode, fchmodat},
    };

    let mode = match private_mode {
        PrivateMode::Directory => Mode::S_IRWXU,
        PrivateMode::File => Mode::S_IRUSR | Mode::S_IWUSR,
    };
    fchmodat(AT_FDCWD, path, mode, FchmodatFlags::NoFollowSymlink).map_err(nix_error)
}

#[cfg(not(unix))]
pub fn create_private_file(path: &std::path::Path) -> Result<fs::File, PlatformError> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(PlatformError::from)
}

#[cfg(not(unix))]
pub fn open_private_lock_file(path: &std::path::Path) -> Result<fs::File, PlatformError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    Ok(file)
}

#[cfg(not(unix))]
pub fn set_private_file_permissions(path: &std::path::Path) -> Result<(), PlatformError> {
    let _ = fs::metadata(path)?;
    Ok(())
}

#[cfg(not(unix))]
pub fn create_private_directory(path: &std::path::Path) -> Result<(), PlatformError> {
    fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn private_directory_uses_mode_0700() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("private");
        create_private_directory(&path).expect("create");
        let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn private_file_uses_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("private");
        fs::write(&path, b"fixture").expect("write");
        set_private_file_permissions(&path).expect("permissions");
        let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn private_file_is_created_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("private-created");
        drop(create_private_file(&path).expect("create"));
        let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn reusable_lock_file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("daemon.lock");
        drop(open_private_lock_file(&path).expect("open"));
        drop(open_private_lock_file(&path).expect("reopen"));
        let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn private_paths_reject_symbolic_links() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("tempdir");
        let target_directory = directory.path().join("target-directory");
        fs::create_dir(&target_directory).expect("target directory");
        let linked_directory = directory.path().join("linked-directory");
        symlink(&target_directory, &linked_directory).expect("directory symlink");
        assert!(create_private_directory(&linked_directory).is_err());

        let target_file = directory.path().join("target-file");
        fs::write(&target_file, b"target").expect("target file");
        let linked_file = directory.path().join("linked-file");
        symlink(&target_file, &linked_file).expect("file symlink");
        assert!(open_private_lock_file(&linked_file).is_err());
        assert_eq!(fs::read(&target_file).expect("target remains"), b"target");

        let hard_link = directory.path().join("hard-link");
        fs::hard_link(&target_file, &hard_link).expect("hard link");
        assert!(open_private_lock_file(&hard_link).is_err());
    }
}
