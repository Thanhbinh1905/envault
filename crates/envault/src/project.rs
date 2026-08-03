//! Per-directory `.envault.toml` manifests and the state `envault load`/`envault
//! unload` use to remember what they previously auto-loaded for a given
//! project path, so a later `envault load` can unload anything dropped from
//! the manifest without touching profiles the user loaded some other way.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use envault_protocol::StructuredError;
use serde::{Deserialize, Serialize};

use crate::input_error;

const MANIFEST_FILE_NAME: &str = ".envault.toml";
const STATE_FILE_NAME: &str = "project_load_state.json";

#[derive(Debug, Default, Deserialize)]
pub struct ProjectManifest {
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub workspaces: Vec<String>,
}

pub fn load_manifest(dir: &Path) -> Result<ProjectManifest, StructuredError> {
    let manifest_path = dir.join(MANIFEST_FILE_NAME);
    let contents = fs::read_to_string(&manifest_path).map_err(|_| {
        input_error(
            "project_config_not_found",
            &format!("No {MANIFEST_FILE_NAME} found in the current directory"),
        )
    })?;
    toml::from_str(&contents).map_err(|error| {
        input_error(
            "project_config_invalid",
            &format!("Failed to parse {MANIFEST_FILE_NAME}: {error}"),
        )
    })
}

pub fn project_key(dir: &Path) -> Result<String, StructuredError> {
    let canonical = fs::canonicalize(dir).map_err(|error| {
        input_error(
            "io_error",
            &format!("Failed to resolve current directory: {error}"),
        )
    })?;
    Ok(canonical.to_string_lossy().into_owned())
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProjectLoadState {
    #[serde(default)]
    pub effective_profiles: Vec<String>,
}

pub type ProjectStateMap = HashMap<String, ProjectLoadState>;

fn state_file_path() -> Result<PathBuf, StructuredError> {
    let dir = envault_platform::data_directory().map_err(|error| {
        input_error(
            "io_error",
            &format!("Failed to resolve data directory: {error}"),
        )
    })?;
    Ok(dir.join(STATE_FILE_NAME))
}

pub fn read_state() -> Result<ProjectStateMap, StructuredError> {
    let path = state_file_path()?;
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ProjectStateMap::new());
        }
        Err(error) => {
            return Err(input_error(
                "io_error",
                &format!("Failed to read project load state: {error}"),
            ));
        }
    };
    serde_json::from_str(&contents).map_err(|error| {
        input_error(
            "io_error",
            &format!("Failed to parse project load state: {error}"),
        )
    })
}

pub fn write_state(state: &ProjectStateMap) -> Result<(), StructuredError> {
    let path = state_file_path()?;
    let parent = path
        .parent()
        .expect("state file path always has a parent (joined onto data_directory())");
    fs::create_dir_all(parent).map_err(|error| {
        input_error(
            "io_error",
            &format!("Failed to create data directory: {error}"),
        )
    })?;
    let rendered = serde_json::to_string_pretty(state).expect("state serializes");
    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, rendered).map_err(|error| {
        input_error(
            "io_error",
            &format!("Failed to write project load state: {error}"),
        )
    })?;
    fs::rename(&tmp_path, &path).map_err(|error| {
        input_error(
            "io_error",
            &format!("Failed to persist project load state: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_defaults_missing_fields_to_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join(MANIFEST_FILE_NAME), "profiles = [\"a\"]\n")
            .expect("write manifest");
        let manifest = load_manifest(dir.path()).expect("manifest parses");
        assert_eq!(manifest.profiles, vec!["a".to_string()]);
        assert!(manifest.workspaces.is_empty());
    }

    #[test]
    fn manifest_missing_file_is_a_usage_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = load_manifest(dir.path()).unwrap_err();
        assert_eq!(error.code, "project_config_not_found");
    }

    #[test]
    fn manifest_invalid_toml_is_a_usage_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join(MANIFEST_FILE_NAME), "not valid toml =").expect("write");
        let error = load_manifest(dir.path()).unwrap_err();
        assert_eq!(error.code, "project_config_invalid");
    }

    #[test]
    fn state_round_trips_through_disk() {
        let mut state = ProjectStateMap::new();
        state.insert(
            "/tmp/example".to_string(),
            ProjectLoadState {
                effective_profiles: vec!["a".to_string(), "b".to_string()],
            },
        );
        // state_file_path() is anchored to envault_platform::data_directory(),
        // which this test does not override; round-trip serde directly instead
        // of hitting the real data directory from a unit test.
        let rendered = serde_json::to_string(&state).expect("serializes");
        let restored: ProjectStateMap = serde_json::from_str(&rendered).expect("deserializes");
        assert_eq!(
            restored.get("/tmp/example").unwrap().effective_profiles,
            vec!["a".to_string(), "b".to_string()]
        );
    }
}
