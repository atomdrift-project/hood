//! Persistent, byte-specific Beamline assessments. Cache failures are always misses.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Once;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::beamline::Assessment;

const TTL: Duration = Duration::from_hours(30 * 24);
const UNMEASURED_TTL: Duration = Duration::from_mins(1);
const MAX_ENTRY_BYTES: u64 = 128 * 1024;

#[derive(Debug)]
pub(crate) struct Cache {
    directory: PathBuf,
    cleanup: Once,
}

#[derive(Deserialize, Serialize)]
struct Entry {
    stored_at: u64,
    assessment: Assessment,
}

impl Cache {
    pub(crate) fn new(mut root: PathBuf, base: &str, token: Option<&str>) -> Self {
        // Keep different endpoints, credentials, and assessment policies isolated.
        // Neither credentials nor PURLs appear in paths or stored cache metadata.
        let scope = serde_json::json!([
            base,
            token,
            crate::beamline::FOLLOW,
            crate::beamline::BUDGET
        ])
        .to_string();
        let digest: [u8; 32] = Sha256::digest(scope.as_bytes()).into();
        let namespace = crate::scanner::hex(&digest);
        root.push(namespace);
        Self {
            directory: root,
            cleanup: Once::new(),
        }
    }

    fn path(&self, sha: &str) -> Option<PathBuf> {
        (sha.len() == 64 && sha.bytes().all(|byte| byte.is_ascii_hexdigit())).then(|| {
            self.directory
                .join(format!("{}.json", sha.to_ascii_lowercase()))
        })
    }

    pub(crate) fn get(&self, sha: &str) -> Option<Assessment> {
        let assessment = self.read(sha);
        if assessment.is_none() {
            self.cleanup.call_once(|| self.prune());
        }
        assessment
    }

    fn read(&self, sha: &str) -> Option<Assessment> {
        let path = self.path(sha)?;
        let mut bytes = Vec::new();
        std::fs::File::open(&path)
            .ok()?
            .take(MAX_ENTRY_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > MAX_ENTRY_BYTES {
            return None;
        }
        let entry: Entry = serde_json::from_slice(&bytes).ok()?;
        if !Self::fresh(&entry, SystemTime::now()) || entry.assessment.classification(sha).is_none()
        {
            // Leave removal to pruning: another process may have replaced this entry.
            return None;
        }
        Some(entry.assessment)
    }

    fn fresh(entry: &Entry, now: SystemTime) -> bool {
        let ttl = if entry
            .assessment
            .engine_version
            .as_ref()
            .is_some_and(|version| !version.is_empty())
        {
            TTL
        } else {
            UNMEASURED_TTL
        };
        now.duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|now| now.as_secs().checked_sub(entry.stored_at))
            .is_some_and(|age| Duration::from_secs(age) < ttl)
    }

    pub(crate) fn put(&self, sha: &str, assessment: Assessment) -> Result<()> {
        if assessment.classification(sha).is_none() {
            return Ok(());
        }
        let Some(path) = self.path(sha) else {
            return Ok(());
        };
        let entry = Entry {
            stored_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            assessment,
        };
        let bytes = serde_json::to_vec(&entry)?;
        if bytes.len() as u64 > MAX_ENTRY_BYTES {
            return Ok(());
        }
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&self.directory)
            .context("create Beamline cache directory")?;
        // A reader sees the old entry or the complete replacement, never a partial write.
        // NamedTempFile also creates private (0600) files on Unix.
        let mut staged = tempfile::NamedTempFile::new_in(&self.directory)?;
        staged.write_all(&bytes)?;
        staged
            .persist(path)
            .context("publish Beamline cache entry")?;
        Ok(())
    }

    /// Reclaim expired files on the first miss; cache hits never walk the directory.
    fn prune(&self) {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return;
        };
        for entry in entries.flatten() {
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "json")
            {
                continue;
            }
            if entry
                .metadata()
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age >= TTL)
            {
                drop(std::fs::remove_file(entry.path()));
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use scan::model::Classification;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn assessment() -> Assessment {
        serde_json::from_value(serde_json::json!({
            "status": "analyzed", "severity": "benign", "sha256": SHA,
            "engine_version": "test-engine", "findings": []
        }))
        .unwrap()
    }

    fn cache(root: &std::path::Path) -> Cache {
        Cache::new(root.into(), "https://api.example", None)
    }

    #[test]
    fn thirty_day_lifetime_is_fixed_and_rejects_future_timestamps() {
        let entry = Entry {
            stored_at: 1_000,
            assessment: assessment(),
        };
        assert_eq!(TTL.as_secs(), 2_592_000);
        for (now, expected) in [
            (999, false),
            (1000, true),
            (2_592_999, true),
            (2_593_000, false),
        ] {
            assert_eq!(
                Cache::fresh(&entry, UNIX_EPOCH + Duration::from_secs(now)),
                expected
            );
        }
    }

    #[test]
    fn unmeasured_evidence_has_short_lifetime() {
        let mut entry = Entry {
            stored_at: 1_000,
            assessment: assessment(),
        };
        entry.assessment.engine_version = None;
        assert!(Cache::fresh(&entry, UNIX_EPOCH + Duration::from_secs(1059)));
        assert!(!Cache::fresh(
            &entry,
            UNIX_EPOCH + Duration::from_secs(1060)
        ));
    }

    #[test]
    fn survives_new_instances_without_refreshing_timestamp_and_is_scoped() {
        let tmp = tempfile::tempdir().unwrap();
        let writer = cache(tmp.path());
        writer.put(SHA, assessment()).unwrap();
        let path = writer.path(SHA).unwrap();
        let before = std::fs::read(&path).unwrap();
        let modified = path.metadata().unwrap().modified().unwrap();
        let reader = cache(tmp.path());
        assert_eq!(
            reader.get(SHA).unwrap().classification(SHA),
            Some(Classification::Benign)
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(path.metadata().unwrap().modified().unwrap(), modified);
        for (base, token) in [
            ("https://other.example", None),
            ("https://api.example", Some("secret-token")),
        ] {
            let isolated = Cache::new(tmp.path().into(), base, token);
            assert!(isolated.get(SHA).is_none());
            assert!(
                !isolated
                    .directory
                    .to_string_lossy()
                    .contains("secret-token")
            );
        }
        assert!(reader.get(&"b".repeat(64)).is_none());
        assert!(reader.get("../../untrusted").is_none());
    }

    #[test]
    fn corrupt_expired_and_mismatched_entries_are_misses() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = cache(tmp.path());
        cache.put(SHA, assessment()).unwrap();
        let path = cache.path(SHA).unwrap();
        for bytes in [
            b"partial json".to_vec(),
            vec![b'x'; usize::try_from(MAX_ENTRY_BYTES + 1).unwrap()],
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(cache.get(SHA).is_none());
        }
        let expired = Entry {
            stored_at: 1,
            assessment: assessment(),
        };
        std::fs::write(&path, serde_json::to_vec(&expired).unwrap()).unwrap();
        assert!(cache.get(SHA).is_none());
        cache.put(SHA, assessment()).unwrap();
        let other = "b".repeat(64);
        std::fs::copy(&path, cache.path(&other).unwrap()).unwrap();
        assert!(cache.get(&other).is_none());
    }

    #[test]
    fn pruning_reclaims_expired_files() {
        let tmp = tempfile::tempdir().unwrap();
        let writer = cache(tmp.path());
        writer.put(SHA, assessment()).unwrap();
        let path = writer.path(SHA).unwrap();
        let expired = Entry {
            stored_at: 1,
            assessment: assessment(),
        };
        std::fs::write(&path, serde_json::to_vec(&expired).unwrap()).unwrap();
        // Windows grants SetFileTime only to a handle opened for writing.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(UNIX_EPOCH)
            .unwrap();
        let reader = cache(tmp.path());
        assert!(reader.get(SHA).is_none());
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn cache_entries_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let cache = cache(tmp.path());
        cache.put(SHA, assessment()).unwrap();
        assert_eq!(
            cache.directory.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            cache
                .path(SHA)
                .unwrap()
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
