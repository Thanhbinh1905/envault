//! Optional, human-only, opt-in convenience unlock: stores the vault's
//! master password in this operating system's native credential store so
//! `start` does not need to prompt on every invocation. See ADR 0014.
//!
//! Only `start` ever reads the stored credential, and only through
//! [`read_stored_password`]. Enabling and disabling both go through the
//! `envault convenience-unlock` command family, never implicitly.

use std::io::{self, Write as _};

use envault_protocol::SensitiveBytes;

const SERVICE: &str = "envault";
const ACCOUNT: &str = "master-password";
const MARKER_FILE_NAME: &str = "convenience-unlock.enabled";

/// Abstracts the OS-native credential store so the orchestration logic here
/// can be tested without touching a real keychain, Credential Manager, or
/// Secret Service session (none of which are reliably available in CI).
pub trait Keystore {
    fn set(&self, secret: &str) -> io::Result<()>;
    fn get(&self) -> io::Result<String>;
    fn delete(&self) -> io::Result<()>;
}

pub struct RealKeystore;

impl Keystore for RealKeystore {
    fn set(&self, secret: &str) -> io::Result<()> {
        entry()?.set_password(secret).map_err(keyring_io_error)
    }

    fn get(&self) -> io::Result<String> {
        entry()?.get_password().map_err(keyring_io_error)
    }

    fn delete(&self) -> io::Result<()> {
        match entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(keyring_io_error(error)),
        }
    }
}

fn entry() -> io::Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(keyring_io_error)
}

fn keyring_io_error(error: keyring::Error) -> io::Error {
    io::Error::other(error)
}

pub fn is_enabled() -> bool {
    marker_path().is_ok_and(|path| path.exists())
}

pub fn enable(password: &SensitiveBytes, keystore: &dyn Keystore) -> io::Result<()> {
    let text = std::str::from_utf8(password.as_slice()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the master password must be valid UTF-8 text to store in the OS credential store",
        )
    })?;
    keystore.set(text)?;
    write_marker()
}

pub fn disable(keystore: &dyn Keystore) -> io::Result<()> {
    keystore.delete()?;
    remove_marker()
}

/// `keystore.get()` returns a plain, non-zeroizing `String` from the
/// `keyring` crate's own API - outside this crate's control. `into_bytes()`
/// below reuses that same buffer rather than copying it, so there is no
/// extra plaintext copy to zero here; the residual exposure is bounded to
/// whatever `keyring` itself does internally, a known and accepted risk.
pub fn read_stored_password(keystore: &dyn Keystore) -> io::Result<SensitiveBytes> {
    let text = keystore.get()?;
    Ok(SensitiveBytes::new(text.into_bytes()))
}

fn marker_path() -> io::Result<std::path::PathBuf> {
    envault_platform::data_directory()
        .map(|directory| directory.join(MARKER_FILE_NAME))
        .map_err(|error| io::Error::other(error.to_string()))
}

fn write_marker() -> io::Result<()> {
    let path = marker_path()?;
    let directory = path
        .parent()
        .expect("the marker path always has a data-directory parent");
    envault_platform::create_private_directory(directory)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let _ = std::fs::remove_file(&path);
    let mut file = envault_platform::create_private_file(&path)
        .map_err(|error| io::Error::other(error.to_string()))?;
    file.write_all(b"{\"version\":1}\n")
}

fn remove_marker() -> io::Result<()> {
    match marker_path() {
        Ok(path) => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        sync::{Mutex, OnceLock},
    };

    use super::*;

    #[derive(Default)]
    struct FakeKeystore {
        stored: RefCell<Option<String>>,
    }

    impl Keystore for FakeKeystore {
        fn set(&self, secret: &str) -> io::Result<()> {
            *self.stored.borrow_mut() = Some(secret.to_owned());
            Ok(())
        }

        fn get(&self) -> io::Result<String> {
            self.stored
                .borrow()
                .clone()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no entry"))
        }

        fn delete(&self) -> io::Result<()> {
            *self.stored.borrow_mut() = None;
            Ok(())
        }
    }

    struct FailingKeystore;

    impl Keystore for FailingKeystore {
        fn set(&self, _secret: &str) -> io::Result<()> {
            Err(io::Error::other("keystore unavailable"))
        }

        fn get(&self) -> io::Result<String> {
            Err(io::Error::other("keystore unavailable"))
        }

        fn delete(&self) -> io::Result<()> {
            Err(io::Error::other("keystore unavailable"))
        }
    }

    // `enable`/`disable` touch a real file under the process's data directory,
    // so tests that exercise the marker file must not run concurrently with
    // each other or with anything else that reads `is_enabled()`.
    fn marker_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn enable_then_disable_round_trips_the_marker_and_stored_secret() {
        let _guard = marker_lock().lock().unwrap();
        let keystore = FakeKeystore::default();
        let password = SensitiveBytes::new(b"correct horse battery staple".to_vec());

        enable(&password, &keystore).expect("enable succeeds");
        assert!(is_enabled(), "marker file must exist once enabled");
        assert_eq!(
            read_stored_password(&keystore)
                .expect("stored password is readable")
                .as_slice(),
            password.as_slice()
        );

        disable(&keystore).expect("disable succeeds");
        assert!(!is_enabled(), "marker file must be removed once disabled");
        assert!(
            keystore.get().is_err(),
            "the stored secret must be gone after disable"
        );
    }

    #[test]
    fn enable_rejects_non_utf8_passwords_without_touching_the_keystore() {
        let _guard = marker_lock().lock().unwrap();
        let keystore = FakeKeystore::default();
        let password = SensitiveBytes::new(vec![0xFF, 0xFE, 0xFD]);

        let result = enable(&password, &keystore);

        assert!(result.is_err());
        assert!(
            keystore.get().is_err(),
            "a rejected password must never reach the keystore"
        );
        assert!(!is_enabled(), "a failed enable must not leave a marker");
    }

    #[test]
    fn a_keystore_failure_during_enable_does_not_leave_a_marker_behind() {
        let _guard = marker_lock().lock().unwrap();
        let password = SensitiveBytes::new(b"correct horse battery staple".to_vec());

        let result = enable(&password, &FailingKeystore);

        assert!(result.is_err());
        assert!(
            !is_enabled(),
            "a failed keystore write must not leave a marker enabled"
        );
    }

    #[test]
    fn disable_is_idempotent_when_nothing_is_enabled() {
        let _guard = marker_lock().lock().unwrap();
        let keystore = FakeKeystore::default();

        disable(&keystore).expect("disabling an already-disabled state is not an error");
        assert!(!is_enabled());
    }
}
