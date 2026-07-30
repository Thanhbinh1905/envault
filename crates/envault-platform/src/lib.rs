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
pub fn create_private_directory(path: &std::path::Path) -> Result<(), PlatformError> {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn create_private_directory(path: &std::path::Path) -> Result<(), PlatformError> {
    fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn private_directory_uses_mode_0700() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("private");
        create_private_directory(&path).expect("create");
        let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
