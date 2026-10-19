//! Process-crash checks using disposable vaults, never real mounts.
#![cfg(all(unix, feature = "async"))]

use oxcrypt_core::vault::{DirId, VaultCreator, VaultOperationsAsync};
use std::{
    fs,
    process::{Child, Command},
    time::{Duration, Instant},
};

const PASSWORD: &str = "durability-test-password";

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "subprocess helper invoked by the crash test"]
fn durability_crash_worker() {
    let vault = std::env::var("OXCRYPT_TEST_CRASH_VAULT").unwrap();
    let ready = std::env::var("OXCRYPT_TEST_CRASH_READY").unwrap();
    let commit = std::env::var("OXCRYPT_TEST_CRASH_COMMIT").unwrap() == "yes";
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let ops = VaultOperationsAsync::open(std::path::Path::new(&vault), PASSWORD).unwrap();
    runtime.block_on(async {
        let mut writer = ops.create_file(&DirId::root(), "note").await.unwrap();
        writer.write(&vec![9; 2 * 1024 * 1024 + 13]).await.unwrap();
        if commit {
            writer.finish().await.unwrap();
            fs::write(ready, b"committed").unwrap();
            std::thread::sleep(Duration::from_secs(30));
        } else {
            fs::write(ready, b"staged").unwrap();
            std::thread::sleep(Duration::from_secs(30));
            drop(writer);
        }
    });
}

#[test]
fn crash_before_or_after_commit_preserves_a_complete_version() {
    for commit in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("vault");
        VaultCreator::new(&vault, PASSWORD).create().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let ops = VaultOperationsAsync::open(&vault, PASSWORD).unwrap();
        let original = vec![3; 32768 + 17];
        runtime
            .block_on(ops.write_file(&DirId::root(), "note", &original))
            .unwrap();
        let ready = temp.path().join("ready");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "durability_crash_worker",
                    "--ignored",
                    "--nocapture",
                ])
                .env("OXCRYPT_TEST_CRASH_VAULT", &vault)
                .env("OXCRYPT_TEST_CRASH_READY", &ready)
                .env(
                    "OXCRYPT_TEST_CRASH_COMMIT",
                    if commit { "yes" } else { "no" },
                )
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "worker exited before ready"
            );
            assert!(Instant::now() < deadline, "worker did not become ready");
            std::thread::sleep(Duration::from_millis(10));
        }
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let reopened = VaultOperationsAsync::open(&vault, PASSWORD).unwrap();
        let actual = runtime
            .block_on(reopened.read_file(&DirId::root(), "note"))
            .unwrap();
        assert_eq!(
            actual.content,
            if commit {
                vec![9; 2 * 1024 * 1024 + 13]
            } else {
                original
            }
        );
        assert_eq!(
            runtime
                .block_on(reopened.list_files(&DirId::root()))
                .unwrap()
                .len(),
            1
        );
    }
}

#[tokio::test]
async fn directory_sync_reports_missing_storage() {
    let temp = tempfile::tempdir().unwrap();
    let vault = temp.path().join("vault");
    VaultCreator::new(&vault, PASSWORD).create().unwrap();
    let ops = VaultOperationsAsync::open(&vault, PASSWORD).unwrap();
    ops.sync_directory(&DirId::root()).await.unwrap();
    let path = ops
        .as_sync()
        .unwrap()
        .calculate_directory_storage_path(&DirId::root())
        .unwrap();
    fs::remove_dir_all(path).unwrap();
    assert!(ops.sync_directory(&DirId::root()).await.is_err());
}
