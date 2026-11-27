//! Passes of local analysis, kept so that the same bytes need neither a
//! second analysis nor the seconds an analyzer takes to load.
//!
//! An entry stands only for the revision that reached it: the rules, the
//! models and the build. Only a pass is kept; a block is rare, and its panel
//! is drawn from the analysis itself. Cache failures are always misses.

use std::path::PathBuf;
use std::sync::Once;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};

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

    /// The risk score this revision passed the bytes `sha` names with.
    pub(crate) fn get(&self, sha: &str) -> Option<f32> {
        let probability = self.read(sha);
        if probability.is_none() {
            self.cleanup.call_once(|| prune(&self.directory));
        }
        probability
    }

    fn read(&self, sha: &str) -> Option<f32> {
        let entry: Entry =
            serde_json::from_slice(&load(&entry_path(&self.directory, sha)?)?).ok()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        // An entry from the future is no younger than one past its time.
        let age = Duration::from_secs(now.as_secs().checked_sub(entry.stored_at)?);
        (entry.revision == self.revision && age < TTL && (0.0..=1.0).contains(&entry.probability))
            .then_some(entry.probability)
    }

    /// Remember that this revision passed the bytes `sha` names.
    pub(crate) fn put(&self, sha: &str, probability: f32) -> Result<()> {
        let Some(path) = entry_path(&self.directory, sha) else {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn cache(root: &std::path::Path, revision: &str) -> VerdictCache {
        VerdictCache::new(root.into(), revision.into())
    }

    #[test]
    fn a_pass_is_remembered_across_instances_for_its_bytes_alone() {
        let tmp = tempfile::tempdir().unwrap();
        cache(tmp.path(), "r1").put(SHA, 0.25).unwrap();
        let reader = cache(tmp.path(), "r1");
        assert_eq!(reader.get(SHA), Some(0.25));
        assert_eq!(reader.get(&"b".repeat(64)), None);
        assert_eq!(reader.get("../../untrusted"), None);
    }

    #[test]
    fn new_rules_or_models_forget_every_pass() {
        let tmp = tempfile::tempdir().unwrap();
        cache(tmp.path(), "r1").put(SHA, 0.0).unwrap();
        assert_eq!(cache(tmp.path(), "r2").get(SHA), None);
        // The newer revision's pass replaces the older one.
        cache(tmp.path(), "r2").put(SHA, 0.5).unwrap();
        assert_eq!(cache(tmp.path(), "r2").get(SHA), Some(0.5));
        assert_eq!(cache(tmp.path(), "r1").get(SHA), None);
    }

    #[test]
    fn corrupt_expired_and_impossible_entries_are_misses() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = cache(tmp.path(), "r1");
        cache.put(SHA, 0.0).unwrap();
        let path = entry_path(tmp.path(), SHA).unwrap();
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
            assert_eq!(cache.get(SHA), None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn entries_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let directory = tmp.path().join("verdicts");
        cache(&directory, "r1").put(SHA, 0.0).unwrap();
        let mode = |path: &std::path::Path| path.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&directory), 0o700);
        assert_eq!(mode(&entry_path(&directory, SHA).unwrap()), 0o600);
    }
}
