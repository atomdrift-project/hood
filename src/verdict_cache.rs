//! Passes of local analysis, kept so that the same bytes need neither a
//! second analysis nor the seconds an analyzer takes to load.
//!
//! An entry stands only for the revision that reached it: the rules, the
//! models and the build. Only a pass is kept; a block is rare, and its panel
//! is drawn from the analysis itself. Cache failures are always misses.
//!
//! A pass covers bytes under the name they were analyzed by. The name is
//! part of the analysis, which types a file by it before its content: were
//! the digest the whole key, bytes first fetched as `notes.txt` would pass
//! unexamined when fetched again as `install.sh`. Entries are named by a
//! digest of both, so no URL is written to disk.

use std::path::PathBuf;
use std::sync::Once;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::beamline_cache::{TTL, entry_path, load, prune, publish};

#[derive(Debug)]
pub(crate) struct VerdictCache {
    directory: PathBuf,
    revision: String,
    cleanup: Once,
}

#[derive(Deserialize, Serialize)]
struct Entry {
    stored_at: u64,
    revision: String,
    probability: f32,
}

impl VerdictCache {
    /// A cache in `directory` of passes reached under `revision`.
    pub(crate) const fn new(directory: PathBuf, revision: String) -> Self {
        Self {
            directory,
            revision,
            cleanup: Once::new(),
        }
    }

    /// The risk score this revision passed the bytes `sha`, named `name`, with.
    pub(crate) fn get(&self, sha: &str, name: &str) -> Option<f32> {
        let probability = self.read(&key(sha, name));
        if probability.is_none() {
            self.cleanup.call_once(|| prune(&self.directory));
        }
        probability
    }

    fn read(&self, key: &str) -> Option<f32> {
        let entry: Entry =
            serde_json::from_slice(&load(&entry_path(&self.directory, key)?)?).ok()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        // An entry from the future is no younger than one past its time.
        let age = Duration::from_secs(now.as_secs().checked_sub(entry.stored_at)?);
        (entry.revision == self.revision && age < TTL && (0.0..=1.0).contains(&entry.probability))
            .then_some(entry.probability)
    }

    /// Remember that this revision passed the bytes `sha`, named `name`.
    pub(crate) fn put(&self, sha: &str, name: &str, probability: f32) -> Result<()> {
        let Some(path) = entry_path(&self.directory, &key(sha, name)) else {
            return Ok(());
        };
        let entry = Entry {
            stored_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            revision: self.revision.clone(),
            probability,
        };
        publish(&self.directory, &path, &serde_json::to_vec(&entry)?)
    }
}

/// What an entry is stored under: a digest of the bytes' own and their name.
fn key(sha: &str, name: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(format!("{sha}\0{name}")).into();
    crate::scanner::hex(&digest)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const URL: &str = "https://private.example/tool/install.sh?token=secret";

    fn cache(root: &std::path::Path, revision: &str) -> VerdictCache {
        VerdictCache::new(root.into(), revision.into())
    }

    #[test]
    fn a_pass_is_remembered_across_instances_for_its_bytes_under_its_name() {
        let tmp = tempfile::tempdir().unwrap();
        cache(tmp.path(), "r1").put(SHA, URL, 0.25).unwrap();
        let reader = cache(tmp.path(), "r1");
        assert_eq!(reader.get(SHA, URL), Some(0.25));
        assert_eq!(reader.get(&"b".repeat(64), URL), None);
        // The same bytes under another name are another analysis.
        assert_eq!(
            reader.get(SHA, "https://private.example/tool/notes.txt"),
            None
        );
    }

    #[test]
    fn no_url_is_written_to_disk() {
        let tmp = tempfile::tempdir().unwrap();
        cache(tmp.path(), "r1").put(SHA, URL, 0.0).unwrap();
        for entry in std::fs::read_dir(tmp.path()).unwrap() {
            let path = entry.unwrap().path();
            let stored = std::fs::read_to_string(&path).unwrap();
            for private in ["private.example", "install.sh", "secret"] {
                assert!(!path.to_string_lossy().contains(private), "{path:?}");
                assert!(!stored.contains(private), "{stored}");
            }
        }
    }

    #[test]
    fn new_rules_or_models_forget_every_pass() {
        let tmp = tempfile::tempdir().unwrap();
        cache(tmp.path(), "r1").put(SHA, URL, 0.0).unwrap();
        assert_eq!(cache(tmp.path(), "r2").get(SHA, URL), None);
        // The newer revision's pass replaces the older one.
        cache(tmp.path(), "r2").put(SHA, URL, 0.5).unwrap();
        assert_eq!(cache(tmp.path(), "r2").get(SHA, URL), Some(0.5));
        assert_eq!(cache(tmp.path(), "r1").get(SHA, URL), None);
    }

    #[test]
    fn corrupt_expired_and_impossible_entries_are_misses() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = cache(tmp.path(), "r1");
        cache.put(SHA, URL, 0.0).unwrap();
        let path = entry_path(tmp.path(), &key(SHA, URL)).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for entry in [
            "partial json".to_owned(),
            format!(
                r#"{{"stored_at":{},"revision":"r1","probability":0.0}}"#,
                now - TTL.as_secs()
            ),
            format!(
                r#"{{"stored_at":{},"revision":"r1","probability":0.0}}"#,
                now + 3600
            ),
            format!(r#"{{"stored_at":{now},"revision":"r1","probability":1.5}}"#),
        ] {
            std::fs::write(&path, entry).unwrap();
            assert_eq!(cache.get(SHA, URL), None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn entries_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let directory = tmp.path().join("verdicts");
        cache(&directory, "r1").put(SHA, URL, 0.0).unwrap();
        let mode = |path: &std::path::Path| path.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&directory), 0o700);
        assert_eq!(
            mode(&entry_path(&directory, &key(SHA, URL)).unwrap()),
            0o600
        );
    }
}
