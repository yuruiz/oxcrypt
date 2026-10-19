use nfsserve::{nfs::filename3, vfs::NFSFileSystem, xdr::XDR};
use oxcrypt_core::{
    crypto::keys::MasterKey,
    vault::{DirId, VaultOperationsAsync},
};
use oxcrypt_nfs::CryptomatorNFS;
use std::sync::Arc;

#[tokio::test]
async fn oversized_read_returns_a_bounded_prefix_with_correct_eof() {
    let temp = tempfile::tempdir().unwrap();
    let ops = Arc::new(VaultOperationsAsync::new(
        temp.path(),
        Arc::new(MasterKey::random().unwrap()),
    ));
    let data: Vec<_> = (0..2 * 1024 * 1024 + 7)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    ops.write_file(&DirId::root(), "large", &data)
        .await
        .unwrap();
    let fs = CryptomatorNFS::new(ops);
    let id = fs
        .lookup(fs.root_dir(), &filename3::from(b"large".to_vec()))
        .await
        .unwrap();
    let (first, eof) = fs.read(id, 0, u32::MAX).await.unwrap();
    assert_eq!(first.len(), 1024 * 1024);
    assert!(!eof);
    assert_eq!(first, data[..first.len()]);
    let mut offset = first.len();
    while offset < data.len() {
        let (bytes, eof) = fs.read(id, offset as u64, u32::MAX).await.unwrap();
        assert!(bytes.len() <= 1024 * 1024);
        assert_eq!(bytes, data[offset..offset + bytes.len()]);
        offset += bytes.len();
        assert_eq!(eof, offset == data.len());
    }
}

#[test]
fn oversized_xdr_lengths_are_rejected_before_allocation() {
    let mut bytes = Vec::<u8>::new();
    let error = bytes
        .deserialize(&mut &((4 * 1024 * 1024 + 1_u32).to_be_bytes())[..])
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(bytes.capacity(), 0);
    let mut words = Vec::<u32>::new();
    let error = words
        .deserialize(&mut &((1024 * 1024 + 1_u32).to_be_bytes())[..])
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(words.capacity(), 0);
}

#[test]
fn maximum_xdr_length_is_rejected_without_reserving_storage() {
    let input = u32::MAX.to_be_bytes();
    let mut bytes = Vec::<u8>::new();
    assert_eq!(
        bytes.deserialize(&mut &input[..]).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(bytes.capacity(), 0);
    let mut words = Vec::<u32>::new();
    assert_eq!(
        words.deserialize(&mut &input[..]).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(words.capacity(), 0);
}
