use oxcrypt_core::vault::{DirId, VaultCreator, VaultOperations};

#[test]
fn creation_refuses_existing_key_material_even_if_config_is_missing() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    let original = VaultCreator::new(&path, "original-password")
        .create()
        .unwrap();
    original
        .write_file(&DirId::root(), "note", b"preserved")
        .unwrap();
    let key_path = path.join("masterkey/masterkey.cryptomator");
    let key_bytes = std::fs::read(&key_path).unwrap();
    std::fs::remove_file(path.join("vault.cryptomator")).unwrap();
    assert!(
        VaultCreator::new(&path, "different-password")
            .create()
            .is_err()
    );
    assert_eq!(std::fs::read(key_path).unwrap(), key_bytes);
    assert_eq!(
        original.read_file(&DirId::root(), "note").unwrap().content,
        b"preserved"
    );
}

#[test]
fn concurrent_initializers_publish_only_one_consistent_vault() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    let start = std::sync::Arc::new(std::sync::Barrier::new(4));
    let workers: Vec<_> = (0..4)
        .map(|index| {
            let path = path.clone();
            let start = std::sync::Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                VaultCreator::new(&path, "same-password")
                    .create()
                    .ok()
                    .map(|ops| {
                        ops.write_file(
                            &DirId::root(),
                            "winner",
                            format!("writer-{index}").as_bytes(),
                        )
                        .unwrap();
                        index
                    })
            })
        })
        .collect();
    let winners: Vec<_> = workers
        .into_iter()
        .filter_map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(winners.len(), 1);
    let ops = VaultOperations::open(&path, "same-password").unwrap();
    assert_eq!(
        ops.read_file(&DirId::root(), "winner").unwrap().content,
        format!("writer-{}", winners[0]).as_bytes()
    );
}

#[test]
fn nested_creation_and_existing_ciphertext_are_handled_without_clobbering() {
    let temp = tempfile::tempdir().unwrap();
    let nested = temp.path().join("new/parents/vault");
    VaultCreator::new(&nested, "password").create().unwrap();
    assert!(VaultOperations::open(&nested, "password").is_ok());
    let occupied = temp.path().join("occupied");
    std::fs::create_dir_all(occupied.join("d")).unwrap();
    std::fs::write(occupied.join("d/data"), b"existing vault data").unwrap();
    assert!(VaultCreator::new(&occupied, "password").create().is_err());
    assert_eq!(
        std::fs::read(occupied.join("d/data")).unwrap(),
        b"existing vault data"
    );
    assert!(!occupied.join("vault.cryptomator").exists());
}

#[cfg(all(unix, feature = "async"))]
#[tokio::test]
async fn password_change_does_not_follow_a_predictable_temporary_symlink() {
    use oxcrypt_core::vault::change_password_async;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "original-password")
        .create()
        .unwrap();
    let sentinel = temp.path().join("sentinel");
    std::fs::write(&sentinel, b"must not be overwritten").unwrap();
    std::os::unix::fs::symlink(&sentinel, path.join("masterkey/masterkey.cryptomator.tmp"))
        .unwrap();
    change_password_async(&path, "original-password", "new-password")
        .await
        .unwrap();
    assert_eq!(std::fs::read(sentinel).unwrap(), b"must not be overwritten");
    assert!(VaultOperations::open(&path, "new-password").is_ok());
    assert!(VaultOperations::open(&path, "original-password").is_err());
}

#[cfg(feature = "async")]
#[tokio::test]
async fn concurrent_password_changes_leave_a_successfully_published_key() {
    use oxcrypt_core::vault::change_password_async;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    let original = VaultCreator::new(&path, "original-password")
        .create()
        .unwrap();
    original
        .write_file(&DirId::root(), "note", b"preserved")
        .unwrap();
    let mut requests = Vec::new();
    for index in 0..4 {
        let path = path.clone();
        requests.push(tokio::spawn(async move {
            let password = format!("new-password-{index}");
            change_password_async(&path, "original-password", &password)
                .await
                .ok()
                .map(|()| password)
        }));
    }
    let mut successful = Vec::new();
    for request in requests {
        if let Some(password) = request.await.unwrap() {
            successful.push(password);
        }
    }
    assert!(!successful.is_empty());
    let readable: Vec<_> = successful
        .iter()
        .filter_map(|password| VaultOperations::open(&path, password).ok())
        .collect();
    assert_eq!(readable.len(), 1);
    assert_eq!(
        readable[0]
            .read_file(&DirId::root(), "note")
            .unwrap()
            .content,
        b"preserved"
    );
}
