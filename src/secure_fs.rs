//! Secure filesystem operations.
//!
//! Provides hardened file I/O for sensitive data:
//! - **Atomic writes**: write-to-temp then rename, preventing partial/corrupt output
//! - **Permission hardening**: on Unix, sensitive files are set to 0o600 (owner read/write only)
//! - **Secure deletion**: multi-pass overwrite with pattern + random data before removal
//!
//! # Limitations
//!
//! Secure deletion is *best-effort*. On modern hardware:
//! - SSDs with wear-leveling may retain copies of overwritten data in spare blocks
//! - CoW filesystems (btrfs, ZFS) may preserve snapshots of previous data
//! - Journaling filesystems may retain copies in the journal
//!
//! Despite these limitations, overwriting remains valuable as defense-in-depth.

use anyhow::{Context, Result};

/// Write data to a file with optional security hardening.
///
/// When `sensitive` is true:
/// - On Unix: creates the temp file with **0o600** (owner read/write only) from
///   the start via `OpenOptionsExt::mode()`, so there is no window of insecure
///   access between creation and permission-set.
/// - Uses `create_new(true)` to prevent race-condition overwrites.
/// - Atomically renames the temp file into place.
///
/// When `sensitive` is false:
/// - Still performs atomic write with `create_new(true)`, but does not restrict
///   permissions.
pub fn write_secure(path: &str, data: &[u8], sensitive: bool) -> Result<()> {
    // Use random suffix to avoid predictable temp-file names and collisions.
    let random_suffix = {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf)
            .map_err(|e| anyhow::anyhow!("getrandom for temp suffix: {:?}", e))?;
        buf.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let temp = format!("{}.tmp.{}", path, random_suffix);

    // Write to temp file.
    // For sensitive files on Unix, create with restricted permissions (0o600)
    // from the start, preventing any window of insecure access.
    if sensitive {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true) // fail if already exists — prevents race
                .mode(0o600) // owner read/write only from creation
                .open(&temp)
                .with_context(|| format!("create temp file (sensitive): {}", temp))?;
            if let Err(e) = file.write_all(data) {
                let _ = std::fs::remove_file(&temp);
                return Err(e).with_context(|| format!("write temp file: {}", temp));
            }
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&temp, data).with_context(|| format!("write temp file: {}", temp))?;
        }
    } else {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // fail if already exists — prevents race
            .open(&temp)
            .with_context(|| format!("create temp file: {}", temp))?;
        if let Err(e) = file.write_all(data) {
            let _ = std::fs::remove_file(&temp);
            return Err(e).with_context(|| format!("write temp file: {}", temp));
        }
    }

    // Atomic rename
    if let Err(e) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp); // clean up on failure
        return Err(e).with_context(|| format!("atomic rename {} -> {}", temp, path));
    }

    Ok(())
}

/// Best-effort file shredding: overwrites with deterministic patterns + random
/// data, then truncates and removes.
///
/// # Important: best-effort only
///
/// This is **not** guaranteed secure deletion on modern hardware:
/// - SSDs with wear-leveling may retain old data in spare blocks
/// - Copy-on-write filesystems (btrfs, ZFS) may preserve snapshots
/// - Journaling filesystems may retain data in their journal
/// - The OS or filesystem may buffer writes and never physically overwrite
///
/// Despite these limitations, overwriting is still worthwhile as one layer of
/// defense-in-depth. For high-assurance deletion, use full-disk encryption
/// and destroy the key.
///
/// # Arguments
///
/// * `path` - Path to the file to delete
/// * `passes` - Number of deterministic pattern passes (1–5). A final random
///   pass is always appended.
///
/// # Errors
///
/// Returns an error if the file cannot be opened, overwritten, or removed.
pub fn secure_delete(path: &str, passes: usize) -> Result<()> {
    use std::io::Write;

    let metadata = std::fs::metadata(path)
        .with_context(|| format!("stat file for secure delete: {}", path))?;
    let size = metadata.len() as usize;

    if size == 0 {
        std::fs::remove_file(path).with_context(|| format!("remove empty file: {}", path))?;
        return Ok(());
    }

    // Deterministic overwrite patterns
    let patterns: &[u8] = &[0x00, 0xFF, 0xAA, 0x55, 0x00];
    let effective_passes = passes.min(patterns.len());

    for (pass, &pattern) in patterns[..effective_passes].iter().enumerate() {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("open file for overwrite pass {}: {}", pass, path))?;

        let buf = vec![pattern; size];
        file.write_all(&buf)
            .with_context(|| format!("overwrite pass {}: {}", pass, path))?;
        file.sync_all()
            .with_context(|| format!("sync pass {}: {}", pass, path))?;
    }

    // Final random-data overwrite
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("open file for random overwrite: {}", path))?;

        let random_data = crate::crypto::random_bytes(size)?;
        file.write_all(&random_data)
            .with_context(|| format!("random overwrite: {}", path))?;
        file.sync_all()
            .with_context(|| format!("sync random overwrite: {}", path))?;
    }

    // Truncate to zero length
    {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("open file for truncation: {}", path))?;
        file.set_len(0)?;
        file.sync_all()?;
    }

    // Remove the file
    std::fs::remove_file(path)
        .with_context(|| format!("remove file after secure delete: {}", path))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_write_secure_normal() {
        let dir = "target/test_secure_fs_normal";
        fs::create_dir_all(dir).unwrap();
        let path = format!("{}/test_normal.txt", dir);

        write_secure(&path, b"hello world", false).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello world");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_write_secure_sensitive() {
        let dir = "target/test_secure_fs_sensitive";
        fs::create_dir_all(dir).unwrap();
        let path = format!("{}/test_sensitive.txt", dir);

        write_secure(&path, b"secret data", true).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "secret data");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_secure_delete() {
        let dir = "target/test_secure_fs_delete";
        fs::create_dir_all(dir).unwrap();
        let path = format!("{}/test_delete.txt", dir);

        fs::write(&path, b"sensitive data to delete").unwrap();
        assert!(std::path::Path::new(&path).exists());

        secure_delete(&path, 3).unwrap();
        assert!(!std::path::Path::new(&path).exists());

        let _ = fs::remove_dir_all(dir);
    }
}
