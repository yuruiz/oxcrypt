use nfsserve::{
    nfs::{filename3, nfs_fh3, sattr3},
    tcp::{NFSTcp, NFSTcpListener},
    vfs::NFSFileSystem,
    xdr::XDR,
};
use oxcrypt_core::{
    crypto::keys::MasterKey,
    vault::{DirId, VaultOperationsAsync},
};
use oxcrypt_nfs::CryptomatorNFS;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Server {
    port: u16,
    root: nfs_fh3,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start(ops: Arc<VaultOperationsAsync>) -> Self {
        let nfs = CryptomatorNFS::new(ops);
        let root = nfs.id_to_fh(nfs.root_dir());
        let listener = NFSTcpListener::bind("127.0.0.1:0", nfs).await.unwrap();
        let port = listener.get_listen_port();
        let task = tokio::spawn(async move {
            listener.handle_forever().await.unwrap();
        });
        Self { port, root, task }
    }
    async fn create(&self, xid: u32, name: &str, mode: u32, verifier: [u8; 8]) -> u32 {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut request = Vec::new();
            for word in [xid, 0, 2, 100003, 3, 8, 0, 0, 0, 0] {
                request.extend_from_slice(&word.to_be_bytes());
            }
            self.root.serialize(&mut request).unwrap();
            filename3::from(name.as_bytes())
                .serialize(&mut request)
                .unwrap();
            mode.serialize(&mut request).unwrap();
            if mode == 2 {
                request.extend_from_slice(&verifier);
            } else {
                sattr3::default().serialize(&mut request).unwrap();
            }
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", self.port))
                .await
                .unwrap();
            stream
                .write_u32(0x8000_0000 | u32::try_from(request.len()).unwrap())
                .await
                .unwrap();
            stream.write_all(&request).await.unwrap();
            let mut reply = Vec::new();
            loop {
                let marker = stream.read_u32().await.unwrap();
                let len = usize::try_from(marker & 0x7fff_ffff).unwrap();
                assert!(len <= 65536);
                let offset = reply.len();
                reply.resize(offset + len, 0);
                stream.read_exact(&mut reply[offset..]).await.unwrap();
                if marker & 0x8000_0000 != 0 {
                    break;
                }
            }
            assert!(reply.len() >= 28);
            let words: Vec<_> = reply[..24]
                .chunks_exact(4)
                .map(|word| u32::from_be_bytes(word.try_into().unwrap()))
                .collect();
            assert_eq!(words, [xid, 1, 0, 0, 0, 0]);
            u32::from_be_bytes(reply[24..28].try_into().unwrap())
        })
        .await
        .expect("NFS CREATE RPC timed out")
    }
}
fn fixture() -> (tempfile::TempDir, Arc<VaultOperationsAsync>) {
    let temp = tempfile::tempdir().unwrap();
    let ops = Arc::new(VaultOperationsAsync::new(
        temp.path(),
        Arc::new(MasterKey::random().unwrap()),
    ));
    std::fs::create_dir_all(
        ops.calculate_directory_storage_path(&DirId::root())
            .unwrap(),
    )
    .unwrap();
    (temp, ops)
}

#[tokio::test]
async fn exclusive_create_replays_the_verifier_and_rejects_a_different_client() {
    let (_temp, ops) = fixture();
    let server = Server::start(ops).await;
    assert_eq!(server.create(1, "exclusive", 2, [42; 8]).await, 0);
    assert_eq!(server.create(2, "exclusive", 2, [42; 8]).await, 0);
    assert_eq!(server.create(3, "exclusive", 2, [43; 8]).await, 17);
}

#[tokio::test]
async fn exclusive_create_verifier_survives_export_restart() {
    let (_temp, ops) = fixture();
    let server = Server::start(Arc::clone(&ops)).await;
    let name = "x".repeat(200);
    let verifier = [0xff, 0xee, 0xdd, 0xcc, 0x99, 0x88, 0x77, 0x66];
    assert_eq!(server.create(1, &name, 2, verifier).await, 0);
    drop(server);
    let server = Server::start(ops).await;
    assert_eq!(server.create(2, &name, 2, verifier).await, 0);
    assert_eq!(server.create(3, &name, 2, [0; 8]).await, 17);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guarded_create_is_atomic_between_rpc_requests_and_preserves_existing_data() {
    let (_temp, ops) = fixture();
    let server = Server::start(Arc::clone(&ops)).await;
    for index in 0..32 {
        let name = format!("race-{index}");
        let (a, b) = tokio::join!(
            server.create(1, &name, 1, [0; 8]),
            server.create(2, &name, 1, [0; 8])
        );
        assert!(
            (a == 0 && b == 17) || (a == 17 && b == 0),
            "both creators must not succeed: {a}, {b}"
        );
    }
    ops.write_file(&DirId::root(), "existing", b"preserved")
        .await
        .unwrap();
    assert_eq!(server.create(3, "existing", 1, [0; 8]).await, 17);
    assert_eq!(
        ops.read_file(&DirId::root(), "existing")
            .await
            .unwrap()
            .content,
        b"preserved"
    );
}

fn frame(xid: u32, procedure: u32, arguments: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for word in [xid, 0, 2, 100003, 3, procedure, 0, 0, 0, 0] {
        body.extend_from_slice(&word.to_be_bytes());
    }
    body.extend_from_slice(arguments);
    let mut framed = (0x8000_0000 | u32::try_from(body.len()).unwrap())
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(&body);
    framed
}

async fn reply(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let marker = stream.read_u32().await.unwrap();
        let len = usize::try_from(marker & 0x7fff_ffff).unwrap();
        assert!(len <= 4 * 1024 * 1024);
        let start = bytes.len();
        bytes.resize(start + len, 0);
        stream.read_exact(&mut bytes[start..]).await.unwrap();
        if marker & 0x8000_0000 != 0 {
            break;
        }
    }
    bytes
}

#[tokio::test]
async fn invalid_rpc_frames_close_before_receiving_oversized_payloads() {
    let (_temp, ops) = fixture();
    let server = Server::start(ops).await;
    for length in [4 * 1024 * 1024 + 1, 0x7fff_ffff] {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port))
            .await
            .unwrap();
        stream.write_u32(0x8000_0000 | length).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), stream.read_u8())
            .await
            .unwrap();
        assert!(result.is_err());
    }
    // Limits apply to the complete record, not just each fragment.
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port))
        .await
        .unwrap();
    stream.write_u32(3 * 1024 * 1024).await.unwrap();
    stream.write_all(&vec![0; 3 * 1024 * 1024]).await.unwrap();
    stream
        .write_u32(0x8000_0000 | 2 * 1024 * 1024)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), stream.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port))
        .await
        .unwrap();
    stream.write_all(&vec![0; 129 * 4]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), stream.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(server.create(9, "still-available", 1, [0; 8]).await, 0);
}

#[tokio::test]
async fn idle_connections_do_not_reserve_request_slots_and_pipelining_progresses() {
    let (_temp, ops) = fixture();
    let server = Server::start(ops).await;
    let mut idle = Vec::new();
    for _ in 0..20 {
        idle.push(
            tokio::net::TcpStream::connect(("127.0.0.1", server.port))
                .await
                .unwrap(),
        );
    }
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut requests = Vec::new();
        for xid in 0..1000 {
            requests.extend(frame(xid, 0, &[]));
        }
        stream.write_all(&requests).await.unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..1000 {
            let response = reply(&mut stream).await;
            assert_eq!(response.len(), 24);
            seen.insert(u32::from_be_bytes(response[..4].try_into().unwrap()));
        }
        assert_eq!(seen.len(), 1000);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn small_readdir_budgets_return_an_error_instead_of_underflowing() {
    let (_temp, ops) = fixture();
    let server = Server::start(ops).await;
    for procedure in [16, 17] {
        let mut arguments = Vec::new();
        server.root.serialize(&mut arguments).unwrap();
        0_u64.serialize(&mut arguments).unwrap();
        arguments.extend_from_slice(&[0; 8]);
        0_u32.serialize(&mut arguments).unwrap();
        if procedure == 17 {
            0_u32.serialize(&mut arguments).unwrap();
        }
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port))
            .await
            .unwrap();
        stream
            .write_all(&frame(1, procedure, &arguments))
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), reply(&mut stream))
            .await
            .unwrap();
        assert_eq!(
            u32::from_be_bytes(response[24..28].try_into().unwrap()),
            10005
        );
    }
}

async fn directory_page(
    server: &Server,
    plus: bool,
    cookie: u64,
    count: u32,
) -> (u32, Vec<(u64, String)>, bool) {
    directory_page_with_limits(server, plus, cookie, count, count).await
}

async fn directory_page_with_limits(
    server: &Server,
    plus: bool,
    cookie: u64,
    dircount: u32,
    count: u32,
) -> (u32, Vec<(u64, String)>, bool) {
    let mut args = Vec::new();
    server.root.serialize(&mut args).unwrap();
    cookie.serialize(&mut args).unwrap();
    args.extend_from_slice(&[0; 8]);
    (if plus { dircount } else { count })
        .serialize(&mut args)
        .unwrap();
    if plus {
        count.serialize(&mut args).unwrap();
    }
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port))
        .await
        .unwrap();
    stream
        .write_all(&frame(1, if plus { 17 } else { 16 }, &args))
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), reply(&mut stream))
        .await
        .unwrap();
    let status = u32::from_be_bytes(response[24..28].try_into().unwrap());
    if status != 0 {
        return (status, Vec::new(), false);
    }
    assert!(
        response.len() - 28 <= count as usize,
        "directory reply exceeds requested budget"
    );
    let mut cursor = std::io::Cursor::new(&response[28..]);
    let mut attrs = nfsserve::nfs::post_op_attr::default();
    attrs.deserialize(&mut cursor).unwrap();
    let mut verifier = [0_u8; 8];
    verifier.deserialize(&mut cursor).unwrap();
    let mut result = Vec::new();
    loop {
        let mut present = false;
        present.deserialize(&mut cursor).unwrap();
        if !present {
            break;
        }
        let mut id = 0_u64;
        id.deserialize(&mut cursor).unwrap();
        let mut name = filename3::default();
        name.deserialize(&mut cursor).unwrap();
        let mut next = 0_u64;
        next.deserialize(&mut cursor).unwrap();
        if plus {
            attrs.deserialize(&mut cursor).unwrap();
            let mut handle = nfsserve::nfs::post_op_fh3::default();
            handle.deserialize(&mut cursor).unwrap();
        }
        result.push((next, String::from_utf8(name.to_vec()).unwrap()));
    }
    let mut eof = false;
    eof.deserialize(&mut cursor).unwrap();
    assert_eq!(cursor.position() as usize, response.len() - 28);
    if plus {
        let bytes: usize = result
            .iter()
            .map(|(_, name)| 24 + name.len().div_ceil(4) * 4)
            .sum();
        assert!(
            bytes <= dircount as usize,
            "directory information exceeds dircount"
        );
    }
    (status, result, eof)
}

#[tokio::test]
async fn readdir_and_readdirplus_advance_through_every_page() {
    let (_temp, ops) = fixture();
    for index in 0..32 {
        ops.write_file(&DirId::root(), &format!("file-{index:02}"), b"")
            .await
            .unwrap();
    }
    let server = Server::start(ops).await;
    for plus in [false, true] {
        let mut seen = std::collections::BTreeSet::new();
        let mut cookie = 0;
        let mut finished = false;
        for _ in 0..40 {
            let (status, entries, eof) = directory_page(&server, plus, cookie, 512).await;
            assert_eq!(status, 0);
            assert!(eof || !entries.is_empty(), "nonterminal page must advance");
            for (next, name) in entries {
                assert!(seen.insert(name), "directory page repeated an entry");
                cookie = next;
            }
            if eof {
                finished = true;
                break;
            }
        }
        assert!(finished);
        assert_eq!(seen.len(), 32);
    }
}

#[tokio::test]
async fn readdir_continues_when_the_last_page_anchor_has_been_deleted() {
    let (_temp, ops) = fixture();
    for index in 0..10 {
        ops.write_file(&DirId::root(), &format!("file-{index:02}"), b"")
            .await
            .unwrap();
    }
    let server = Server::start(Arc::clone(&ops)).await;
    let (_, first, eof) = directory_page(&server, true, 0, 1024).await;
    assert!(!eof);
    assert!(first.len() >= 2);
    let (cookie, name) = first.last().unwrap();
    ops.delete_file(&DirId::root(), name).await.unwrap();
    let (status, second, _) = directory_page(&server, true, *cookie, 1024).await;
    assert_eq!(status, 0);
    assert!(!second.is_empty());
    assert!(
        second
            .iter()
            .all(|(_, name)| first.iter().all(|(_, previous)| previous != name))
    );
}

#[tokio::test]
async fn directory_budget_that_cannot_fit_one_entry_returns_toosmall() {
    let (_temp, ops) = fixture();
    ops.write_file(&DirId::root(), &"x".repeat(200), b"")
        .await
        .unwrap();
    let server = Server::start(ops).await;
    for plus in [false, true] {
        assert_eq!(directory_page(&server, plus, 0, 256).await.0, 10005);
    }
}

#[tokio::test]
async fn directory_pages_accept_exact_xdr_budgets_and_reject_one_byte_less() {
    let (_temp, ops) = fixture();
    ops.write_file(&DirId::root(), "abc", b"").await.unwrap();
    let server = Server::start(ops).await;
    // resok: post_op_attr (88), verifier (8), list terminator and EOF (8).
    // Entry: present (4), fileid (8), padded name (8), cookie (8).
    let base = 104;
    let entry = 28;
    // PLUS adds attributes (88) and a present 24-byte file handle (32).
    for (plus, count) in [(false, base + entry), (true, base + entry + 120)] {
        let (status, entries, eof) =
            directory_page_with_limits(&server, plus, 0, entry, count).await;
        assert_eq!(status, 0);
        assert_eq!(entries.len(), 1);
        assert!(eof);
        assert_eq!(
            directory_page_with_limits(&server, plus, 0, entry, count - 1)
                .await
                .0,
            10005
        );
    }
    assert_eq!(
        directory_page_with_limits(&server, true, 0, entry - 1, 1024)
            .await
            .0,
        10005
    );
    assert_eq!(
        directory_page_with_limits(&server, true, 0, 0, 1024)
            .await
            .0,
        10005
    );
}

#[tokio::test]
async fn empty_directory_pages_finish_even_with_zero_dircount() {
    let (_temp, ops) = fixture();
    let server = Server::start(ops).await;
    for plus in [false, true] {
        let (status, entries, eof) = directory_page_with_limits(&server, plus, 0, 0, 104).await;
        assert_eq!(status, 0);
        assert!(entries.is_empty());
        assert!(eof);
        assert_eq!(
            directory_page_with_limits(&server, plus, 0, 0, 103).await.0,
            10005
        );
    }
}

#[tokio::test]
async fn readdir_cookies_survive_mutations_and_report_exact_page_eof() {
    let (_temp, ops) = fixture();
    let nfs = CryptomatorNFS::new(ops);
    let root = nfs.root_dir();
    for name in ["a", "b", "c", "d"] {
        nfs.create(root, &filename3::from(name.as_bytes()), sattr3::default())
            .await
            .unwrap();
    }
    let first = nfs.readdir(root, 0, 2).await.unwrap();
    assert!(!first.end);
    let anchor = first.entries.last().unwrap().fileid;
    nfs.remove(root, &filename3::from(&b"b"[..])).await.unwrap();
    nfs.rename(
        root,
        &filename3::from(&b"a"[..]),
        root,
        &filename3::from(&b"z"[..]),
    )
    .await
    .unwrap();
    nfs.create(root, &filename3::from(&b"aa"[..]), sattr3::default())
        .await
        .unwrap();
    let next = nfs.readdir(root, anchor, 3).await.unwrap();
    assert!(next.end, "an exact final page must advertise EOF");
    assert_eq!(
        next.entries
            .iter()
            .map(|entry| entry.name.to_vec())
            .collect::<Vec<_>>(),
        [b"c".to_vec(), b"d".to_vec(), b"aa".to_vec()]
    );
    let last_cookie = next.entries.last().unwrap().fileid;
    let last = nfs.readdir(root, last_cookie, 2).await.unwrap();
    assert!(last.end);
    assert!(last.entries.is_empty());
}
