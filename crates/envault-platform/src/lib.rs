#![forbid(unsafe_code)]

use std::{env, fs, io, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("no user data directory is available")]
    MissingDataDirectory,
    #[error("filesystem operation failed")]
    Io(#[from] io::Error),
    #[error("file exceeds the configured size limit")]
    FileTooLarge,
}

pub fn read_bounded_regular_file(
    path: &std::path::Path,
    maximum_bytes: usize,
) -> Result<Vec<u8>, PlatformError> {
    read_bounded_file(path, maximum_bytes, false)
}

pub fn read_bounded_private_file(
    path: &std::path::Path,
    maximum_bytes: usize,
) -> Result<Vec<u8>, PlatformError> {
    read_bounded_file(path, maximum_bytes, true)
}

#[cfg(unix)]
fn read_bounded_file(
    path: &std::path::Path,
    maximum_bytes: usize,
    require_private_mode: bool,
) -> Result<Vec<u8>, PlatformError> {
    use std::{fs::File, io::Read};

    use nix::{
        fcntl::{OFlag, openat},
        sys::stat::Mode,
    };

    let (parent, name) = open_stable_parent(path)?;
    let descriptor = openat(
        &parent,
        name.as_os_str(),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(nix_error)?;
    let mut file = File::from(descriptor);
    validate_private_regular_file(&file, require_private_mode)?;
    let length =
        usize::try_from(file.metadata()?.len()).map_err(|_| PlatformError::FileTooLarge)?;
    if length > maximum_bytes {
        return Err(PlatformError::FileTooLarge);
    }
    let mut bytes = Vec::with_capacity(length.min(maximum_bytes));
    file.by_ref()
        .take(
            u64::try_from(maximum_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err(PlatformError::FileTooLarge);
    }
    validate_private_regular_file(&file, require_private_mode)?;
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_bounded_file(
    path: &std::path::Path,
    maximum_bytes: usize,
    _require_private_mode: bool,
) -> Result<Vec<u8>, PlatformError> {
    use std::io::Read;

    let mut file = fs::OpenOptions::new().read(true).open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(invalid_private_path());
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(
            u64::try_from(maximum_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err(PlatformError::FileTooLarge);
    }
    Ok(bytes)
}

#[cfg(unix)]
pub fn publish_private_file_no_replace(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), PlatformError> {
    use std::{fs::File, os::unix::fs::PermissionsExt};

    use nix::{
        fcntl::{OFlag, openat},
        sys::stat::Mode,
    };
    use rustix::fs::{RenameFlags, renameat_with};

    if source.parent() != destination.parent() {
        return Err(invalid_private_path());
    }
    let (parent, source_name) = open_stable_parent(source)?;
    let destination_name = destination.file_name().ok_or_else(invalid_private_path)?;
    let descriptor = openat(
        &parent,
        source_name.as_os_str(),
        OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(nix_error)?;
    let source_file = File::from(descriptor);
    validate_private_regular_file(&source_file, false)?;
    source_file.set_permissions(fs::Permissions::from_mode(0o600))?;
    validate_private_regular_file(&source_file, true)?;
    source_file.sync_all()?;
    let source_metadata = source_file.metadata()?;
    renameat_with(
        &parent,
        source_name.as_os_str(),
        &parent,
        destination_name,
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| PlatformError::Io(error.into()))?;
    let destination_descriptor = openat(
        &parent,
        destination_name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(nix_error)?;
    let destination_file = File::from(destination_descriptor);
    validate_same_private_file(&source_metadata, &destination_file)?;
    File::from(parent).sync_all()?;
    Ok(())
}

#[cfg(unix)]
pub fn validate_private_file_path(
    path: &std::path::Path,
    expected: &fs::File,
) -> Result<(), PlatformError> {
    use nix::{
        fcntl::{OFlag, openat},
        sys::stat::Mode,
    };

    validate_private_regular_file(expected, true)?;
    let expected_metadata = expected.metadata()?;
    let (parent, name) = open_stable_parent(path)?;
    let descriptor = openat(
        &parent,
        name.as_os_str(),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(nix_error)?;
    let actual = fs::File::from(descriptor);
    validate_same_private_file(&expected_metadata, &actual)
}

#[cfg(not(unix))]
pub fn publish_private_file_no_replace(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), PlatformError> {
    if source.parent() != destination.parent() {
        return Err(invalid_private_path());
    }
    set_private_file_permissions(source)?;
    fs::hard_link(source, destination)?;
    if let Err(error) = fs::remove_file(source) {
        let _ = fs::remove_file(destination);
        return Err(PlatformError::Io(error));
    }
    set_private_file_permissions(destination)?;
    sync_parent_directory(destination)?;
    Ok(())
}

#[cfg(not(unix))]
pub fn validate_private_file_path(
    path: &std::path::Path,
    expected: &fs::File,
) -> Result<(), PlatformError> {
    if !expected.metadata()?.file_type().is_file() || !fs::metadata(path)?.file_type().is_file() {
        return Err(invalid_private_path());
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_directory(path: &std::path::Path) -> Result<(), PlatformError> {
    let _ = path.parent().ok_or_else(invalid_private_path)?;
    Ok(())
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
    use std::os::unix::fs::PermissionsExt;

    use nix::{
        fcntl::{OFlag, openat},
        sys::stat::Mode,
    };

    let (parent, name) = open_stable_parent(path)?;
    let descriptor = openat(
        parent,
        name.as_os_str(),
        OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(nix_error)?;
    let file = fs::File::from(descriptor);
    validate_private_regular_file(&file, false)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    validate_private_regular_file(&file, true)?;
    Ok(())
}

#[cfg(unix)]
pub fn set_private_socket_permissions(path: &std::path::Path) -> Result<(), PlatformError> {
    use nix::{
        fcntl::AtFlags,
        sys::stat::{FchmodatFlags, Mode, SFlag, fchmodat, fstatat},
    };

    let (parent, name) = open_stable_parent(path)?;
    let before =
        fstatat(&parent, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW).map_err(nix_error)?;
    if SFlag::from_bits_truncate(before.st_mode) & SFlag::S_IFMT != SFlag::S_IFSOCK
        || before.st_nlink != 1
    {
        return Err(invalid_private_path());
    }
    fchmodat(
        &parent,
        name.as_os_str(),
        Mode::S_IRUSR | Mode::S_IWUSR,
        FchmodatFlags::NoFollowSymlink,
    )
    .map_err(nix_error)?;
    let after =
        fstatat(&parent, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW).map_err(nix_error)?;
    if SFlag::from_bits_truncate(after.st_mode) & SFlag::S_IFMT != SFlag::S_IFSOCK
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || after.st_nlink != 1
        || after.st_mode & 0o777 != 0o600
    {
        return Err(invalid_private_path());
    }
    Ok(())
}

#[cfg(unix)]
pub fn create_private_file(path: &std::path::Path) -> Result<fs::File, PlatformError> {
    use nix::{
        fcntl::{OFlag, openat},
        sys::stat::Mode,
    };

    let (parent, name) = open_stable_parent(path)?;
    let descriptor = openat(
        parent,
        name.as_os_str(),
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(nix_error)?;
    let file = fs::File::from(descriptor);
    validate_private_regular_file(&file, true)?;
    Ok(file)
}

#[cfg(unix)]
pub fn open_private_lock_file(path: &std::path::Path) -> Result<fs::File, PlatformError> {
    use std::os::unix::fs::PermissionsExt;

    use nix::{
        fcntl::{OFlag, openat},
        sys::stat::Mode,
    };

    let (parent, name) = open_stable_parent(path)?;
    let descriptor = openat(
        parent,
        name.as_os_str(),
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(nix_error)?;
    let file = fs::File::from(descriptor);
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
fn validate_same_private_file(
    expected: &fs::Metadata,
    actual: &fs::File,
) -> Result<(), PlatformError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let actual = actual.metadata()?;
    if !actual.file_type().is_file()
        || actual.nlink() != 1
        || actual.permissions().mode() & 0o777 != 0o600
        || expected.dev() != actual.dev()
        || expected.ino() != actual.ino()
    {
        return Err(invalid_private_path());
    }
    Ok(())
}

#[cfg(unix)]
fn open_stable_parent(
    path: &std::path::Path,
) -> Result<(std::os::fd::OwnedFd, std::ffi::OsString), PlatformError> {
    use std::path::Component;

    use nix::{
        fcntl::{OFlag, open, openat},
        sys::stat::Mode,
    };

    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(invalid_private_path)?
        .to_os_string();
    let parent = path.parent().ok_or_else(invalid_private_path)?;
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
    let mut descriptor = open(
        if parent.is_absolute() {
            std::path::Path::new("/")
        } else {
            std::path::Path::new(".")
        },
        flags,
        Mode::empty(),
    )
    .map_err(nix_error)?;
    for component in parent.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(component) => {
                descriptor =
                    openat(&descriptor, component, flags, Mode::empty()).map_err(nix_error)?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(invalid_private_path());
            }
        }
    }
    Ok((descriptor, name))
}

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
pub fn set_private_socket_permissions(path: &std::path::Path) -> Result<(), PlatformError> {
    set_private_file_permissions(path)
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
    fn private_socket_uses_mode_0600() {
        use std::{os::unix::fs::PermissionsExt, os::unix::net::UnixListener};

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("socket");
        let listener = UnixListener::bind(&path).expect("bind");
        set_private_socket_permissions(&path).expect("permissions");
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
        drop(listener);
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

    #[test]
    fn bounded_reads_and_creates_reject_symbolic_link_parents() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("tempdir");
        let actual_parent = directory.path().join("actual");
        fs::create_dir(&actual_parent).expect("actual parent");
        let input = actual_parent.join("input");
        fs::write(&input, b"secret").expect("input");
        set_private_file_permissions(&input).expect("private input");
        let linked_parent = directory.path().join("linked");
        symlink(&actual_parent, &linked_parent).expect("parent symlink");

        assert!(read_bounded_regular_file(&linked_parent.join("input"), 32).is_err());
        assert!(read_bounded_private_file(&linked_parent.join("input"), 32).is_err());
        assert!(create_private_file(&linked_parent.join("output")).is_err());
        assert!(open_private_lock_file(&linked_parent.join("lock")).is_err());
        assert!(set_private_file_permissions(&linked_parent.join("input")).is_err());
        assert!(!actual_parent.join("output").exists());
    }

    #[test]
    fn stable_path_operations_reject_parent_traversal() {
        let directory = tempfile::tempdir().expect("tempdir");
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).expect("nested");
        let traversing = nested.join("..").join("output");

        assert!(create_private_file(&traversing).is_err());
        assert!(!directory.path().join("output").exists());
    }

    #[test]
    fn bounded_private_read_rejects_public_mode_and_oversized_data() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("input");
        fs::write(&path, b"secret").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("public mode");
        assert!(read_bounded_private_file(&path, 32).is_err());
        set_private_file_permissions(&path).expect("private mode");
        assert_eq!(
            read_bounded_private_file(&path, 32).expect("read"),
            b"secret"
        );
        assert!(matches!(
            read_bounded_private_file(&path, 3),
            Err(PlatformError::FileTooLarge)
        ));
    }

    #[test]
    fn private_publish_is_no_replace_and_mode_0600() {
        use std::{io::Write as _, os::unix::fs::PermissionsExt};

        let directory = tempfile::tempdir().expect("tempdir");
        let source = directory.path().join("temporary");
        let destination = directory.path().join("package");
        let mut file = create_private_file(&source).expect("create");
        file.write_all(b"package").expect("write");
        file.sync_all().expect("sync");
        drop(file);
        publish_private_file_no_replace(&source, &destination).expect("publish");
        assert!(!source.exists());
        assert_eq!(fs::read(&destination).expect("read"), b"package");
        assert_eq!(
            fs::metadata(&destination)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let replacement = directory.path().join("replacement");
        drop(create_private_file(&replacement).expect("replacement"));
        assert!(publish_private_file_no_replace(&replacement, &destination).is_err());
        assert_eq!(fs::read(&destination).expect("unchanged"), b"package");
    }

    #[test]
    fn private_publish_rejects_symbolic_link_parent() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("tempdir");
        let actual_parent = directory.path().join("actual");
        fs::create_dir(&actual_parent).expect("actual parent");
        let source = actual_parent.join("temporary");
        fs::write(&source, b"secret").expect("source");
        set_private_file_permissions(&source).expect("private source");
        let linked_parent = directory.path().join("linked");
        symlink(&actual_parent, &linked_parent).expect("parent symlink");

        assert!(
            publish_private_file_no_replace(
                &linked_parent.join("temporary"),
                &linked_parent.join("output")
            )
            .is_err()
        );
        assert_eq!(fs::read(source).expect("source remains"), b"secret");
        assert!(!actual_parent.join("output").exists());
    }

    #[test]
    fn private_file_path_validation_rejects_replacement() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("output");
        let file = create_private_file(&path).expect("create");
        validate_private_file_path(&path, &file).expect("owned path");
        fs::remove_file(&path).expect("unlink");
        drop(create_private_file(&path).expect("replacement"));
        assert!(validate_private_file_path(&path, &file).is_err());
    }
}
