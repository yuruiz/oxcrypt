#![cfg(all(unix, feature = "webdav"))]

use std::{
    io::{Read, Write},
    net::TcpStream,
    path::Path,
    process::Command,
    time::Duration,
};

fn cli(config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oxcrypt"));
    command
        .env("OXCRYPT_CONFIG_DIR", config)
        .env("OXCRYPT_PASSWORD", "daemon-test-password")
        .env("OXCRYPT_NO_STARTUP_CLEANUP", "1")
        // Prevent automatic OS mounting; this exercises the server-only path.
        .env("PATH", config.join("no-external-commands"));
    command
}

struct DaemonGuard(u32);

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Ok(pid) = i32::try_from(self.0) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
    }
}

#[test]
fn background_webdav_publishes_usable_url_and_unmounts_without_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    std::fs::create_dir(&config).unwrap();
    let vault = dir.path().join("vault");
    let mountpoint = dir.path().join("mount");
    let init = cli(&config).arg("init").arg(&vault).output().unwrap();
    assert!(init.status.success(), "{:?}", init);

    let mounted = assert_cmd::Command::from_std(cli(&config))
        .args(["mount", "--backend", "webdav"])
        .arg(&vault)
        .arg(&mountpoint)
        .timeout(Duration::from_secs(40))
        .output()
        .unwrap();
    assert!(mounted.status.success(), "{:?}", mounted);
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(config.join("mounts.json")).unwrap()).unwrap();
    let entry = &state["mounts"][0];
    let _daemon = DaemonGuard(u32::try_from(entry["pid"].as_u64().unwrap()).unwrap());
    let url = entry["display_location"].as_str().unwrap();
    assert!(String::from_utf8_lossy(&mounted.stderr).contains(url));

    let address = url.strip_prefix("http://").unwrap().trim_end_matches('/');
    let mut connection = TcpStream::connect(address).unwrap();
    connection
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    connection
        .write_all(
            format!("PROPFIND / HTTP/1.1\r\nHost: {address}\r\nDepth: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
    let mut response = String::new();
    connection.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 207"), "{response}");

    // A second daemon at the same logical mountpoint must not hide the first.
    let duplicate = assert_cmd::Command::from_std(cli(&config))
        .args(["mount", "--backend", "webdav"])
        .arg(&vault)
        .arg(&mountpoint)
        .timeout(Duration::from_secs(10))
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert!(TcpStream::connect(address).is_ok());

    // Exercise normal startup cleanup as well as the mounts command's cleanup.
    let listing = cli(&config)
        .env_remove("OXCRYPT_NO_STARTUP_CLEANUP")
        .args(["mounts", "--json"])
        .output()
        .unwrap();
    assert!(listing.status.success(), "{:?}", listing);
    let listing: serde_json::Value = serde_json::from_slice(&listing.stdout).unwrap();
    assert_eq!(listing["active"].as_array().unwrap().len(), 1);
    assert_eq!(listing["active"][0]["location"], url);
    assert_eq!(listing["active"][0]["display_location"], url);
    let table = cli(&config).arg("mounts").output().unwrap();
    assert!(table.status.success());
    assert!(String::from_utf8_lossy(&table.stdout).contains(url));

    if mountpoint.exists() {
        std::fs::remove_dir(&mountpoint).unwrap();
    }
    let unmounted = assert_cmd::Command::from_std(cli(&config))
        .arg("unmount")
        .arg(&mountpoint)
        .timeout(Duration::from_secs(15))
        .output()
        .unwrap();
    assert!(unmounted.status.success(), "{:?}", unmounted);
    assert!(TcpStream::connect(address).is_err());
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(config.join("mounts.json")).unwrap()).unwrap();
    assert!(state["mounts"].as_array().unwrap().is_empty());
}

#[test]
fn failed_background_mount_does_not_claim_readiness() {
    let dir = tempfile::tempdir().unwrap();
    let invalid_vault = dir.path().join("invalid-vault");
    std::fs::create_dir(&invalid_vault).unwrap();
    let output = assert_cmd::Command::from_std(cli(dir.path()))
        .args(["mount", "--backend", "webdav"])
        .arg(invalid_vault)
        .arg(dir.path().join("mount"))
        .timeout(Duration::from_secs(10))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("exited before becoming ready"), "{stderr}");
    assert!(!stderr.contains("Mount started in background"), "{stderr}");
}
