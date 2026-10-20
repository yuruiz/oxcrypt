//! pjdfstest POSIX compliance tests for oxcrypt-fuse.
//!
//! This module runs the pjdfstest suite against a mounted Cryptomator vault
//! to verify POSIX filesystem semantics.
//!
//! ## Test Categories
//!
//! pjdfstest supports testing these syscalls:
//! - chmod, chown - permission/ownership (requires setattr)
//! - mkdir, rmdir - directory operations
//! - open, unlink - file creation/deletion
//! - link - hard links (not supported by Cryptomator)
//! - symlink, readlink - symbolic links
//! - rename - move/rename operations
//! - truncate, ftruncate - size changes (requires setattr)
//! - utimensat - timestamp changes (requires setattr)
//! - mknod, mkfifo - special files (not supported)
//! - chflags - file flags (BSD only)
//! - posix_fallocate - space allocation (not supported)
//!
//! ## Requirements
//!
//! - pjdfstest must be in PATH (available via devenv, or set PJDFSTEST_BIN env var)
//! - FUSE must be installed (fuse3 on Linux, macFUSE on macOS)
//! - Each test creates its own disposable vault
//!
//! ## Running Tests
//!
//! ```bash
//! # Run all FUSE integration tests
//! cargo nextest run -p oxcrypt-fuse --features fuse-tests
//!
//! # Run specific category
//! cargo nextest run -p oxcrypt-fuse --features fuse-tests -E 'test(mkdir)'
//! ```

#![cfg(all(unix, feature = "fuse-tests"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fuser::{BackgroundSession, MountOption};
use oxcrypt_fuse::filesystem::CryptomatorFS;
use oxcrypt_mount::testing::TempVault;
use tempfile::TempDir;

/// Get the path to the pjdfstest binary.
fn pjdfstest_bin() -> Option<PathBuf> {
    // Check environment variable first
    if let Ok(bin) = std::env::var("PJDFSTEST_BIN") {
        let path = PathBuf::from(&bin);
        if path.exists() {
            return Some(path);
        }
    }

    // Check common Nix store locations
    if let Ok(entries) = fs::read_dir("/nix/store") {
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name();
            if name.to_string_lossy().contains("pjdfstest") {
                let bin_path = entry.path().join("bin/pjdfstest");
                if bin_path.exists() {
                    return Some(bin_path);
                }
            }
        }
    }

    // Fall back to PATH lookup
    if Command::new("pjdfstest")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
    {
        return Some(PathBuf::from("pjdfstest"));
    }

    None
}

fn pjdfstest_available() -> bool {
    pjdfstest_bin().is_some()
}

fn fuse_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/dev/fuse").exists()
    }
    #[cfg(target_os = "macos")]
    {
        Path::new("/Library/Filesystems/macfuse.fs").exists()
            || Path::new("/Library/Filesystems/osxfuse.fs").exists()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// RAII guard for mounted filesystem.
struct MountGuard {
    session: Option<BackgroundSession>,
    mount_point: PathBuf,
    _vault: TempVault,
    _mount_dir: TempDir,
}

impl MountGuard {
    fn new(
        session: BackgroundSession,
        mount_point: PathBuf,
        vault: TempVault,
        mount_dir: TempDir,
    ) -> Self {
        Self {
            session: Some(session),
            mount_point,
            _vault: vault,
            _mount_dir: mount_dir,
        }
    }

    fn mount_point(&self) -> &Path {
        &self.mount_point
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            if let Err(error) = session.umount_and_join() {
                eprintln!("Failed to unmount disposable test vault: {error}");
                assert!(
                    std::thread::panicking(),
                    "FUSE test cleanup failed: {error}"
                );
            }
        }
    }
}

/// Mount the test vault with read-write access.
fn mount_test_vault_rw(temp_dir: TempDir) -> Result<MountGuard, String> {
    let mount_dir = temp_dir.path().join("mnt");
    fs::create_dir(&mount_dir).map_err(|error| error.to_string())?;
    let vault = TempVault::new();
    let fs = CryptomatorFS::new(vault.path(), TempVault::password())
        .map_err(|e| format!("Failed to create CryptomatorFS: {e}"))?;

    let options = vec![MountOption::FSName("cryptomator".to_string())];

    // `auto_unmount` is not used: it requires a non-owner session ACL, which would
    // make the decrypted mount readable by other local users. The session is
    // unmounted when it is dropped at the end of the test.
    let mut config = fuser::Config::default();
    config.mount_options = options;

    let session = fuser::spawn_mount(fs, &mount_dir, &config)
        .map_err(|e| format!("Failed to mount: {}", e))?;

    Ok(MountGuard::new(session, mount_dir, vault, temp_dir))
}

/// Run a pjdfstest syscall and return (success, stdout, stderr).
fn run_pjdfstest_raw(
    workdir: &Path,
    syscall: &str,
    args: &[&str],
) -> Result<(bool, String, String), String> {
    let bin = pjdfstest_bin().ok_or("pjdfstest binary not found")?;

    let output = Command::new(&bin)
        .current_dir(workdir)
        .arg(syscall)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run pjdfstest: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok((output.status.success(), stdout, stderr))
}

/// Run a pjdfstest syscall, returning true if it succeeded.
fn run_pjdfstest(workdir: &Path, syscall: &str, args: &[&str]) -> Result<bool, String> {
    let (success, stdout, stderr) = run_pjdfstest_raw(workdir, syscall, args)?;

    if !success {
        eprintln!("pjdfstest {} {:?} failed:", syscall, args);
        eprintln!("  stdout: {}", stdout.trim());
        eprintln!("  stderr: {}", stderr.trim());
    }

    Ok(success)
}

/// A missing fixture invalidates every assertion that depends on it.
fn require_pjdfstest_success(workdir: &Path, syscall: &str, args: &[&str]) {
    let (success, stdout, stderr) = run_pjdfstest_raw(workdir, syscall, args)
        .unwrap_or_else(|error| panic!("Fixture {syscall} {args:?} failed: {error}"));
    assert!(
        success,
        "Fixture {syscall} {args:?} failed: stdout={stdout:?}, stderr={stderr:?}"
    );
}

/// Result of a pjdfstest category.
#[derive(Debug, Default, Clone)]
struct TestResult {
    passed: usize,
    failed: usize,
    skipped: usize,
    errors: Vec<String>,
}

impl TestResult {
    fn success_rate(&self) -> f64 {
        let total = self.passed + self.failed;
        if total == 0 {
            100.0
        } else {
            (self.passed as f64 / total as f64) * 100.0
        }
    }

    fn add_pass(&mut self) {
        self.passed += 1;
    }

    fn add_fail(&mut self, msg: String) {
        self.failed += 1;
        self.errors.push(msg);
    }

    fn expect_errno(&mut self, workdir: &Path, syscall: &str, args: &[&str], errors: &[&str]) {
        match run_pjdfstest_raw(workdir, syscall, args) {
            Ok((false, stdout, _)) if errors.contains(&stdout.trim()) => self.add_pass(),
            Ok((success, stdout, stderr)) => self.add_fail(format!(
                "{syscall} {args:?}: expected {errors:?}, success={success}, stdout={stdout:?}, stderr={stderr:?}"
            )),
            Err(error) => self.add_fail(error),
        }
    }

    fn print_summary(&self, category: &str) {
        println!(
            "{} tests: {} passed, {} failed, {} skipped ({:.1}% success)",
            category,
            self.passed,
            self.failed,
            self.skipped,
            self.success_rate()
        );
        for err in &self.errors {
            eprintln!("  - {}", err);
        }
        assert_eq!(self.failed, 0, "{category} tests failed: {self:?}");
    }
}

/// Skip check macro
macro_rules! skip_if_not_ready {
    () => {
        if !fuse_available() {
            assert!(
                std::env::var_os("OXCRYPT_REQUIRE_FUSE").is_none(),
                "FUSE is required but unavailable"
            );
            eprintln!("Skipping: FUSE not available");
            return;
        }
        if !pjdfstest_available() {
            assert!(
                std::env::var_os("OXCRYPT_REQUIRE_FUSE").is_none(),
                "pjdfstest is required but unavailable"
            );
            eprintln!("Skipping: pjdfstest not in PATH (run with devenv or set PJDFSTEST_BIN)");
            return;
        }
    };
}

/// Setup test directory and return guard + test dir path.
fn setup_test(name: &str) -> Option<(MountGuard, PathBuf)> {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let guard = mount_test_vault_rw(temp_dir).expect("Failed to mount disposable test vault");

    let test_dir = guard.mount_point().join(format!("pjdfstest_{}", name));
    fs::create_dir_all(&test_dir).expect("Failed to create test directory");

    Some((guard, test_dir))
}

// ============================================================================
// PASSING TESTS - These should all pass
// ============================================================================

/// mkdir/rmdir - Directory creation and removal.
/// Status: PASS
#[test]
fn test_pjdfstest_mkdir() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("mkdir") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    // Test various permission modes
    for mode in ["0755", "0700", "0777", "0750"] {
        let dir_name = format!("dir_{}", mode);
        match run_pjdfstest(&test_dir, "mkdir", &[&dir_name, mode]) {
            Ok(true) => result.add_pass(),
            Ok(false) => result.add_fail(format!("mkdir {} {}", dir_name, mode)),
            Err(e) => {
                eprintln!("Error: {}", e);
                result.add_fail(e);
            }
        }
        // Clean up
        let _ = run_pjdfstest(&test_dir, "rmdir", &[&dir_name]);
    }

    // Test nested mkdir (should fail - parent doesn't exist)
    result.expect_errno(
        &test_dir,
        "mkdir",
        &["nested/deep/dir", "0755"],
        &["ENOENT"],
    );

    // Test rmdir on non-empty dir (should fail)
    require_pjdfstest_success(&test_dir, "mkdir", &["nonempty", "0755"]);
    require_pjdfstest_success(&test_dir, "open", &["nonempty/file", "O_CREAT", "0644"]);
    result.expect_errno(&test_dir, "rmdir", &["nonempty"], &["ENOTEMPTY", "EEXIST"]);
    // Clean up
    let _ = run_pjdfstest(&test_dir, "unlink", &["nonempty/file"]);
    let _ = run_pjdfstest(&test_dir, "rmdir", &["nonempty"]);

    result.print_summary("mkdir");
    assert!(result.failed == 0, "mkdir tests failed: {:?}", result);
}

/// open/create - File creation with various flags.
/// Status: PASS
#[test]
fn test_pjdfstest_open() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("open") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    // Basic file creation
    for (i, mode) in ["0644", "0600", "0666", "0400"].iter().enumerate() {
        let filename = format!("file_{}", i);
        match run_pjdfstest(&test_dir, "open", &[&filename, "O_CREAT", mode]) {
            Ok(true) => result.add_pass(),
            Ok(false) => result.add_fail(format!("open {} O_CREAT {}", filename, mode)),
            Err(e) => {
                eprintln!("Error: {}", e);
                result.add_fail(e);
            }
        }
        let _ = run_pjdfstest(&test_dir, "unlink", &[&filename]);
    }

    // O_CREAT|O_EXCL - should fail if file exists
    require_pjdfstest_success(&test_dir, "open", &["excl_test", "O_CREAT", "0644"]);
    result.expect_errno(
        &test_dir,
        "open",
        &["excl_test", "O_CREAT|O_EXCL", "0644"],
        &["EEXIST"],
    );
    let _ = run_pjdfstest(&test_dir, "unlink", &["excl_test"]);

    // O_CREAT|O_EXCL on new file - should succeed
    match run_pjdfstest(&test_dir, "open", &["excl_new", "O_CREAT|O_EXCL", "0644"]) {
        Ok(true) => result.add_pass(),
        Ok(false) => result.add_fail("O_EXCL on new file should succeed".into()),
        Err(e) => {
            eprintln!("Error: {}", e);
            result.add_fail(e);
        }
    }
    let _ = run_pjdfstest(&test_dir, "unlink", &["excl_new"]);

    result.print_summary("open");
    assert!(result.failed == 0, "open tests failed: {:?}", result);
}

/// symlink - Symbolic link creation and removal.
/// Status: PASS (readlink not supported by pjdfstest on macOS)
#[test]
fn test_pjdfstest_symlink() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("symlink") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    // Create symlinks with various targets
    let targets = ["target1", "../relative", "/absolute/path", "a/b/c/deep"];
    for (i, target) in targets.iter().enumerate() {
        let link_name = format!("link_{}", i);
        match run_pjdfstest(&test_dir, "symlink", &[target, &link_name]) {
            Ok(true) => result.add_pass(),
            Ok(false) => result.add_fail(format!("symlink {} -> {}", link_name, target)),
            Err(e) => {
                eprintln!("Error: {}", e);
                result.add_fail(e);
            }
        }
        let _ = run_pjdfstest(&test_dir, "unlink", &[&link_name]);
    }

    // Symlink over existing file should fail
    require_pjdfstest_success(&test_dir, "open", &["existing", "O_CREAT", "0644"]);
    result.expect_errno(&test_dir, "symlink", &["target", "existing"], &["EEXIST"]);
    let _ = run_pjdfstest(&test_dir, "unlink", &["existing"]);

    result.print_summary("symlink");
    assert!(result.failed == 0, "symlink tests failed: {:?}", result);
}

// ============================================================================
// KNOWN FAILING TESTS - These reveal bugs to fix
// ============================================================================

/// rename - File and directory renaming.
/// Checks immediate visibility and replacement after file creation.
#[test]
fn test_pjdfstest_rename() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("rename") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    // Create file and rename it
    require_pjdfstest_success(&test_dir, "open", &["src_file", "O_CREAT", "0644"]);
    match run_pjdfstest(&test_dir, "rename", &["src_file", "dst_file"]) {
        Ok(true) => result.add_pass(),
        Ok(false) => result.add_fail("rename src_file -> dst_file".into()),
        Err(e) => {
            eprintln!("Error: {}", e);
            result.add_fail(e);
        }
    }
    let _ = run_pjdfstest(&test_dir, "unlink", &["dst_file"]);

    // Rename directory
    require_pjdfstest_success(&test_dir, "mkdir", &["src_dir", "0755"]);
    match run_pjdfstest(&test_dir, "rename", &["src_dir", "dst_dir"]) {
        Ok(true) => result.add_pass(),
        Ok(false) => result.add_fail("rename src_dir -> dst_dir".into()),
        Err(e) => {
            eprintln!("Error: {}", e);
            result.add_fail(e);
        }
    }
    let _ = run_pjdfstest(&test_dir, "rmdir", &["dst_dir"]);

    // Rename over existing file (should succeed, replacing target)
    require_pjdfstest_success(&test_dir, "open", &["src2", "O_CREAT", "0644"]);
    require_pjdfstest_success(&test_dir, "open", &["dst2", "O_CREAT", "0644"]);
    match run_pjdfstest(&test_dir, "rename", &["src2", "dst2"]) {
        Ok(true) => result.add_pass(),
        Ok(false) => result.add_fail("rename over existing should succeed".into()),
        Err(e) => {
            eprintln!("Error: {}", e);
            result.add_fail(e);
        }
    }
    let _ = run_pjdfstest(&test_dir, "unlink", &["dst2"]);

    result.print_summary("rename");
}

/// unlink - File deletion.
/// Checks immediate deletion after file creation.
#[test]
fn test_pjdfstest_unlink() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("unlink") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    // Create and immediately unlink files
    for i in 0..5 {
        let filename = format!("file_{}", i);
        require_pjdfstest_success(&test_dir, "open", &[&filename, "O_CREAT", "0644"]);
        match run_pjdfstest(&test_dir, "unlink", &[&filename]) {
            Ok(true) => result.add_pass(),
            Ok(false) => result.add_fail(format!("unlink {}", filename)),
            Err(e) => {
                eprintln!("Error: {}", e);
                result.add_fail(e);
            }
        }
    }

    // Unlink non-existent file should fail
    result.expect_errno(&test_dir, "unlink", &["nonexistent"], &["ENOENT"]);

    // Unlink directory should fail (use rmdir instead)
    require_pjdfstest_success(&test_dir, "mkdir", &["adir", "0755"]);
    result.expect_errno(&test_dir, "unlink", &["adir"], &["EISDIR", "EPERM"]);
    let _ = run_pjdfstest(&test_dir, "rmdir", &["adir"]);

    result.print_summary("unlink");
}

/// truncate - File size modification.
/// Status: IMPLEMENTED via setattr
#[test]
fn test_pjdfstest_truncate() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("truncate") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    // Create a file and truncate to various sizes
    require_pjdfstest_success(&test_dir, "open", &["trunc_file", "O_CREAT", "0644"]);

    for size in ["0", "100", "1024", "65536", "0"] {
        match run_pjdfstest(&test_dir, "truncate", &["trunc_file", size]) {
            Ok(true) => result.add_pass(),
            Ok(false) => result.add_fail(format!("truncate to {}", size)),
            Err(e) => {
                eprintln!("Error: {}", e);
                result.add_fail(e);
            }
        }
    }

    let _ = run_pjdfstest(&test_dir, "unlink", &["trunc_file"]);

    // Truncate non-existent file should fail
    result.expect_errno(&test_dir, "truncate", &["nonexistent", "0"], &["ENOENT"]);

    result.print_summary("truncate");
    assert!(result.failed == 0, "truncate tests failed: {:?}", result);
}

/// ftruncate - Truncate via file handle.
/// Status: IMPLEMENTED via setattr
#[test]
fn test_pjdfstest_ftruncate() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("ftruncate") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    // Descriptor 0 refers to the first file opened in this pjdfstest process.
    match run_pjdfstest(
        &test_dir,
        "open",
        &[
            "ftrunc_file",
            "O_CREAT|O_RDWR",
            "0644",
            ":",
            "ftruncate",
            "0",
            "1024",
        ],
    ) {
        Ok(true) => result.add_pass(),
        Ok(false) => result.add_fail("ftruncate through an open descriptor".into()),
        Err(e) => {
            eprintln!("Error: {}", e);
            result.add_fail(e);
        }
    }
    assert_eq!(
        fs::metadata(test_dir.join("ftrunc_file")).unwrap().len(),
        1024
    );

    let _ = run_pjdfstest(&test_dir, "unlink", &["ftrunc_file"]);

    result.print_summary("ftruncate");
    assert!(result.failed == 0, "ftruncate tests failed: {:?}", result);
}

/// chmod - Permission modification.
/// Status: NOT SUPPORTED - Cryptomator doesn't store Unix permissions, returns ENOTSUP
#[test]
#[ignore = "NOT SUPPORTED: Cryptomator doesn't store Unix permissions"]
fn test_pjdfstest_chmod() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("chmod") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    // Create a file and try to change permissions
    require_pjdfstest_success(&test_dir, "open", &["chmod_file", "O_CREAT", "0644"]);

    // chmod should fail with ENOTSUP - Cryptomator doesn't store permissions
    for mode in ["0755", "0700", "0600"] {
        result.expect_errno(
            &test_dir,
            "chmod",
            &["chmod_file", mode],
            &["ENOTSUP", "EOPNOTSUPP"],
        );
    }

    let _ = run_pjdfstest(&test_dir, "unlink", &["chmod_file"]);
    result.print_summary("chmod");
    eprintln!("NOT SUPPORTED: Cryptomator doesn't store Unix permissions (returns ENOTSUP)");
}

/// chown - Ownership modification.
/// Status: NOT SUPPORTED - Cryptomator doesn't store Unix ownership, returns ENOTSUP
#[test]
#[ignore = "NOT SUPPORTED: Cryptomator doesn't store Unix ownership"]
fn test_pjdfstest_chown() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("chown") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    // Create a file
    require_pjdfstest_success(&test_dir, "open", &["chown_file", "O_CREAT", "0644"]);

    // chown should fail with ENOTSUP - Cryptomator doesn't store ownership
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    result.expect_errno(
        &test_dir,
        "chown",
        &["chown_file", &uid.to_string(), &gid.to_string()],
        &["ENOTSUP", "EOPNOTSUPP"],
    );

    let _ = run_pjdfstest(&test_dir, "unlink", &["chown_file"]);
    result.print_summary("chown");
    eprintln!("NOT SUPPORTED: Cryptomator doesn't store Unix ownership (returns ENOTSUP)");
}

/// link - Hard link creation.
/// Status: NOT SUPPORTED - Cryptomator doesn't support hard links
#[test]
#[ignore = "requires FUSE and pjdfstest - NOT SUPPORTED: hard links"]
fn test_pjdfstest_link() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("link") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    // Create a file and try to hard link it
    require_pjdfstest_success(&test_dir, "open", &["link_src", "O_CREAT", "0644"]);

    match run_pjdfstest(&test_dir, "link", &["link_src", "link_dst"]) {
        Ok(true) => result.add_pass(),
        Ok(false) => result.add_fail("link src -> dst".into()),
        Err(e) => {
            eprintln!("Error: {}", e);
            result.add_fail(e);
        }
    }

    let _ = run_pjdfstest(&test_dir, "unlink", &["link_src"]);
    let _ = run_pjdfstest(&test_dir, "unlink", &["link_dst"]);

    result.print_summary("link");
    if result.failed > 0 {
        eprintln!("NOT SUPPORTED: Cryptomator format doesn't support hard links");
    }
}

/// utimensat - Timestamp modification.
/// Status: IMPLEMENTED - setattr returns success for atime/mtime but doesn't persist them.
/// Cryptomator doesn't store Unix timestamps; we return success for compatibility with
/// tools like touch, tar, rsync that expect to set timestamps. The syscall succeeds but
/// the timestamps remain unchanged (derived from underlying encrypted file metadata).
#[test]
fn test_pjdfstest_utimensat() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("utimensat") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    // Create a file
    require_pjdfstest_success(&test_dir, "open", &["utime_file", "O_CREAT", "0644"]);

    // utimensat takes dirfd, path, both timestamps, and flags.
    match run_pjdfstest(
        &test_dir,
        "utimensat",
        &[
            "AT_FDCWD",
            "utime_file",
            "1000000000",
            "0",
            "1000000000",
            "0",
            "0",
        ],
    ) {
        Ok(true) => result.add_pass(),
        Ok(false) => result.add_fail("utimensat specific time".into()),
        Err(e) => {
            eprintln!("Error: {}", e);
            result.add_fail(e);
        }
    }

    // UTIME_NOW
    match run_pjdfstest(
        &test_dir,
        "utimensat",
        &[
            "AT_FDCWD",
            "utime_file",
            "0",
            "UTIME_NOW",
            "0",
            "UTIME_NOW",
            "0",
        ],
    ) {
        Ok(true) => result.add_pass(),
        Ok(false) => result.add_fail("utimensat UTIME_NOW".into()),
        Err(e) => {
            eprintln!("Error: {}", e);
            result.add_fail(e);
        }
    }

    let _ = run_pjdfstest(&test_dir, "unlink", &["utime_file"]);

    result.print_summary("utimensat");
    assert!(result.failed == 0, "utimensat tests failed: {:?}", result);
}

/// mknod - Create special files.
/// Status: NOT SUPPORTED - Cryptomator only supports files, dirs, symlinks
#[test]
#[ignore = "requires FUSE and pjdfstest - NOT SUPPORTED: special files"]
fn test_pjdfstest_mknod() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("mknod") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    // Regular file via mknod
    match run_pjdfstest(
        &test_dir,
        "mknod",
        &["mknod_file", "S_IFREG", "0644", "0", "0"],
    ) {
        Ok(true) => result.add_pass(),
        Ok(false) => result.add_fail("mknod S_IFREG".into()),
        Err(e) => {
            eprintln!("Error: {}", e);
            result.add_fail(e);
        }
    }
    let _ = run_pjdfstest(&test_dir, "unlink", &["mknod_file"]);

    // Character device (likely to fail - needs root and we don't support it)
    result.expect_errno(
        &test_dir,
        "mknod",
        &["char_dev", "S_IFCHR", "0644", "1", "3"],
        &["ENOSYS", "ENOTSUP", "EOPNOTSUPP", "EPERM"],
    );

    result.print_summary("mknod");
    if result.failed > 0 {
        eprintln!("NOT SUPPORTED: Special files not supported by Cryptomator");
    }
}

/// mkfifo - Create named pipes.
/// Status: NOT SUPPORTED - Cryptomator only supports files, dirs, symlinks
#[test]
#[ignore = "requires FUSE and pjdfstest - NOT SUPPORTED: FIFOs"]
fn test_pjdfstest_mkfifo() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("mkfifo") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    result.expect_errno(
        &test_dir,
        "mkfifo",
        &["test_fifo", "0644"],
        &["ENOSYS", "ENOTSUP", "EOPNOTSUPP"],
    );

    result.print_summary("mkfifo");
    eprintln!("NOT SUPPORTED: FIFOs not supported by Cryptomator");
}

/// posix_fallocate - Preallocate file space.
/// Status: IMPLEMENTED (mode=0 only)
#[test]
#[cfg_attr(target_os = "macos", ignore = "macOS does not provide posix_fallocate")]
fn test_pjdfstest_posix_fallocate() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("fallocate") {
        Some(t) => t,
        None => return,
    };

    let mut result = TestResult::default();

    // Allocate 1MB using the descriptor opened in the same process.
    match run_pjdfstest(
        &test_dir,
        "open",
        &[
            "falloc_file",
            "O_CREAT|O_RDWR",
            "0644",
            ":",
            "posix_fallocate",
            "0",
            "0",
            "1048576",
        ],
    ) {
        Ok(true) => result.add_pass(),
        Ok(false) => result.add_fail("posix_fallocate 1MB".into()),
        Err(e) => {
            eprintln!("Error: {}", e);
            result.add_fail(e);
        }
    }
    assert_eq!(
        fs::metadata(test_dir.join("falloc_file")).unwrap().len(),
        1048576
    );

    let _ = run_pjdfstest(&test_dir, "unlink", &["falloc_file"]);

    result.print_summary("posix_fallocate");
    assert!(
        result.failed == 0,
        "posix_fallocate tests failed: {:?}",
        result
    );
}

// ============================================================================
// COMPREHENSIVE DIAGNOSTIC TEST
// ============================================================================

/// Comprehensive test that runs all operations and reports overall status.
/// This is for diagnostics - it doesn't assert failures.
#[test]
#[ignore = "requires FUSE and pjdfstest - diagnostic test"]
fn test_pjdfstest_all_operations() {
    skip_if_not_ready!();

    let (_guard, test_dir) = match setup_test("all") {
        Some(t) => t,
        None => return,
    };

    println!("\n{}", "=".repeat(60));
    println!("pjdfstest Comprehensive Diagnostic");
    println!("{}\n", "=".repeat(60));

    let categories: Vec<(&str, &str, Vec<(&str, Vec<&str>)>)> = vec![
        (
            "mkdir",
            "IMPLEMENTED",
            vec![
                ("mkdir", vec!["testdir", "0755"]),
                ("rmdir", vec!["testdir"]),
            ],
        ),
        (
            "open",
            "IMPLEMENTED",
            vec![
                ("open", vec!["testfile", "O_CREAT", "0644"]),
                ("unlink", vec!["testfile"]),
            ],
        ),
        (
            "symlink",
            "IMPLEMENTED",
            vec![
                ("symlink", vec!["target", "testlink"]),
                ("unlink", vec!["testlink"]),
            ],
        ),
        (
            "rename",
            "IMPLEMENTED",
            vec![
                ("open", vec!["rename_src", "O_CREAT", "0644"]),
                ("rename", vec!["rename_src", "rename_dst"]),
            ],
        ),
        (
            "chmod",
            "NOT IMPL",
            vec![
                ("open", vec!["chmod_file", "O_CREAT", "0644"]),
                ("chmod", vec!["chmod_file", "0755"]),
            ],
        ),
        (
            "truncate",
            "NOT IMPL",
            vec![
                ("open", vec!["trunc_file", "O_CREAT", "0644"]),
                ("truncate", vec!["trunc_file", "1024"]),
            ],
        ),
        (
            "link",
            "NOT SUPPORTED",
            vec![
                ("open", vec!["link_src", "O_CREAT", "0644"]),
                ("link", vec!["link_src", "link_dst"]),
            ],
        ),
        (
            "mkfifo",
            "NOT SUPPORTED",
            vec![("mkfifo", vec!["test_fifo", "0644"])],
        ),
    ];

    let mut summary: Vec<(&str, &str, usize, usize)> = vec![];

    for (category, status, operations) in &categories {
        println!("\n--- {} ({}) ---", category, status);
        let mut passed = 0;
        let mut failed = 0;

        for (syscall, args) in operations {
            match run_pjdfstest(&test_dir, syscall, args) {
                Ok(true) => {
                    println!("  [PASS] {} {:?}", syscall, args);
                    passed += 1;
                }
                Ok(false) => {
                    println!("  [FAIL] {} {:?}", syscall, args);
                    failed += 1;
                }
                Err(e) => {
                    println!("  [ERR]  {} {:?}: {}", syscall, args, e);
                    failed += 1;
                }
            }
        }

        summary.push((category, status, passed, failed));
    }

    // Print summary table
    println!("\n{}", "=".repeat(60));
    println!("SUMMARY");
    println!("{}", "=".repeat(60));
    println!(
        "{:<15} {:<15} {:>6} {:>6}",
        "Category", "Status", "Pass", "Fail"
    );
    println!("{:-<15} {:-<15} {:->6} {:->6}", "", "", "", "");

    let mut total_pass = 0;
    let mut total_fail = 0;
    for (cat, status, pass, fail) in &summary {
        println!("{:<15} {:<15} {:>6} {:>6}", cat, status, pass, fail);
        total_pass += pass;
        total_fail += fail;
    }
    println!("{:-<15} {:-<15} {:->6} {:->6}", "", "", "", "");
    println!(
        "{:<15} {:<15} {:>6} {:>6}",
        "TOTAL", "", total_pass, total_fail
    );

    println!("\nLegend:");
    println!("  IMPLEMENTED  - Should work");
    println!("  BUG:*        - Has known bugs");
    println!("  NOT IMPL     - Requires setattr (ENOSYS)");
    println!("  NOT SUPPORTED- Not possible with Cryptomator format");
}
