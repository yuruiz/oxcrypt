//! Bounded-memory authenticated random-access editing of existing ciphertext.
use crate::fs::streaming::{
    CHUNK_PLAINTEXT_SIZE, VaultFileReaderSync, chunk_to_encrypted_offset_for_cipher,
};
use crate::{crypto::keys::MasterKey, vault::config::CipherCombo};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// Encryption work performed by an editor, excluding header authentication.
#[derive(Debug, Default, Clone, Copy)]
pub struct EditStats {
    /// Number of old content chunks decrypted.
    pub decrypted_chunks: u64,
    /// Number of changed content chunks encrypted.
    pub encrypted_chunks: u64,
    /// Ciphertext bytes copied when filesystem cloning was unavailable.
    pub copied_ciphertext_bytes: u64,
}

#[derive(Debug)]
struct Stage {
    _directory: tempfile::TempDir,
    file: File,
}

#[derive(Debug, PartialEq)]
struct Identity {
    length: u64,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    device_inode: (u64, u64),
}
impl Identity {
    fn of(metadata: &fs::Metadata) -> io::Result<Self> {
        Ok(Self {
            length: metadata.len(),
            modified: metadata.modified()?,
            #[cfg(unix)]
            device_inode: {
                use std::os::unix::fs::MetadataExt;
                (metadata.dev(), metadata.ino())
            },
        })
    }
}

/// An editor keeps one dirty plaintext chunk and stages only ciphertext on disk.
/// Unchanged chunks retain their header, nonce and authentication tag. Commits
/// atomically replace the complete ciphertext, using filesystem COW when possible.
pub struct VaultFileEditor {
    reader: VaultFileReaderSync,
    stage: Option<Stage>,
    staging_root: PathBuf,
    size: u64,
    dirty: bool,
    dirty_chunk: Option<(u64, Zeroizing<Vec<u8>>)>,
    expected: Option<Identity>,
    stats: EditStats,
}

impl std::fmt::Debug for VaultFileEditor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultFileEditor")
            .field("size", &self.size)
            .field("dirty", &self.dirty)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl VaultFileEditor {
    /// Open an existing encrypted file without reading its content chunks.
    pub fn open(
        path: &Path,
        key: &MasterKey,
        cipher: CipherCombo,
        staging_root: &Path,
    ) -> io::Result<Self> {
        let reader =
            VaultFileReaderSync::open_with_cipher(path, key, cipher).map_err(io::Error::other)?;
        let size = reader.plaintext_size();
        let expected = Some(Identity::of(&reader.file.metadata()?)?);
        Ok(Self {
            reader,
            stage: None,
            staging_root: staging_root.to_owned(),
            size,
            dirty: false,
            dirty_chunk: None,
            expected,
            stats: EditStats::default(),
        })
    }

    /// Create an empty editor, staging its authenticated header immediately.
    pub fn create(key: &MasterKey, cipher: CipherCombo, staging_root: &Path) -> io::Result<Self> {
        let directory = tempfile::tempdir_in(staging_root)?;
        let path = directory.path().join("content");
        fs::write(
            &path,
            cipher.encrypt_file(&[], key).map_err(io::Error::other)?,
        )?;
        let mut editor = Self::open(&path, key, cipher, staging_root)?;
        editor.stage = Some(Stage {
            file: OpenOptions::new().read(true).write(true).open(&path)?,
            _directory: directory,
        });
        editor.expected = None;
        editor.dirty = true;
        Ok(editor)
    }

    /// Current plaintext length.
    pub fn len(&self) -> u64 {
        self.size
    }
    /// Whether the file has no plaintext bytes.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
    /// Whether the stage differs from the committed file.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
    /// Crypto and fallback copy counters.
    pub fn stats(&self) -> EditStats {
        self.stats
    }
    /// Resident dirty plaintext, excluding caller-owned read/write buffers.
    pub fn buffered_plaintext_bytes(&self) -> usize {
        self.dirty_chunk
            .as_ref()
            .map_or(0, |(_, bytes)| bytes.len())
    }

    /// Cipher combination used by the file.
    pub fn cipher(&self) -> CipherCombo {
        self.reader.decryptor.cipher_combo
    }

    fn overhead(&self) -> usize {
        if self.cipher() == CipherCombo::SivGcm {
            28
        } else {
            48
        }
    }
    fn offset(&self, chunk: u64) -> u64 {
        chunk_to_encrypted_offset_for_cipher(chunk, self.cipher())
    }
    fn ensure_stage(&mut self) -> io::Result<()> {
        if self.stage.is_none() {
            let directory = tempfile::tempdir_in(&self.staging_root)?;
            let (file, copied) =
                clone_ciphertext(&mut self.reader.file, &directory.path().join("content"))?;
            self.stats.copied_ciphertext_bytes += copied;
            self.stage = Some(Stage {
                _directory: directory,
                file,
            });
        }
        Ok(())
    }
    // Chunk offsets and lengths are bounded by the 32 KiB format limit.
    #[allow(clippy::cast_possible_truncation)]
    fn load(&mut self, chunk: u64) -> io::Result<Zeroizing<Vec<u8>>> {
        if let Some((number, data)) = &self.dirty_chunk
            && *number == chunk
        {
            return Ok(data.clone());
        }
        let begin = chunk * CHUNK_PLAINTEXT_SIZE as u64;
        if begin >= self.size {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let length =
            (self.size - begin).min(CHUNK_PLAINTEXT_SIZE as u64) as usize + self.overhead();
        let offset = self.offset(chunk);
        let file = self
            .stage
            .as_mut()
            .map_or(&mut self.reader.file, |stage| &mut stage.file);
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes)?;
        let data = self
            .reader
            .decryptor
            .decrypt_chunk(chunk, &bytes)
            .map_err(io::Error::other)?;
        self.stats.decrypted_chunks += 1;
        Ok(Zeroizing::new(data))
    }
    fn flush_chunk(&mut self) -> io::Result<()> {
        if let Some((chunk, plaintext)) = &self.dirty_chunk {
            let encrypted = self.reader.decryptor.encrypt_chunk(*chunk, plaintext)?;
            let offset = self.offset(*chunk);
            let stage = self
                .stage
                .as_mut()
                .ok_or_else(|| io::Error::other("missing edit stage"))?;
            stage.file.seek(SeekFrom::Start(offset))?;
            stage.file.write_all(&encrypted)?;
            self.stats.encrypted_chunks += 1;
            self.dirty_chunk = None;
        }
        Ok(())
    }

    /// Read just the authenticated chunks intersecting the requested range.
    // The result length is clamped to the caller's usize-sized request.
    #[allow(clippy::cast_possible_truncation)]
    pub fn read(&mut self, offset: u64, length: usize) -> io::Result<Vec<u8>> {
        let length = (self.size.saturating_sub(offset)).min(length as u64) as usize;
        let mut result = Vec::new();
        result.try_reserve(length).map_err(io::Error::other)?;
        let mut position = offset;
        while result.len() < length {
            let chunk = position / CHUNK_PLAINTEXT_SIZE as u64;
            let within = (position % CHUNK_PLAINTEXT_SIZE as u64) as usize;
            let data = self.load(chunk)?;
            let count = (length - result.len()).min(data.len() - within);
            result.extend_from_slice(&data[within..within + count]);
            position += count as u64;
        }
        Ok(result)
    }

    /// Change a byte range; fully overwritten chunks require no old decryption.
    // Per-chunk indices are always below CHUNK_PLAINTEXT_SIZE.
    #[allow(clippy::cast_possible_truncation)]
    pub fn write(&mut self, offset: u64, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(data.len() as u64)
            .filter(|end| i64::try_from(*end).is_ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file offset overflow"))?;
        if offset > self.size {
            self.resize(offset)?;
        }
        self.ensure_stage()?;
        let mut position = offset;
        let mut written = 0;
        while written < data.len() {
            let chunk = position / CHUNK_PLAINTEXT_SIZE as u64;
            let within = (position % CHUNK_PLAINTEXT_SIZE as u64) as usize;
            let count = (CHUNK_PLAINTEXT_SIZE - within).min(data.len() - written);
            if self
                .dirty_chunk
                .as_ref()
                .is_none_or(|(number, _)| *number != chunk)
            {
                self.flush_chunk()?;
            }
            let mut bytes = if within == 0 && count == CHUNK_PLAINTEXT_SIZE {
                Zeroizing::new(Vec::new())
            } else {
                self.load(chunk)?
            };
            let length = bytes.len().max(within + count);
            bytes.resize(length, 0);
            bytes[within..within + count].copy_from_slice(&data[written..written + count]);
            self.dirty_chunk = Some((chunk, bytes));
            self.size = self.size.max(position + count as u64);
            self.dirty = true;
            written += count;
            position += count as u64;
        }
        debug_assert!(self.size >= end);
        Ok(written)
    }

    /// Resize, authenticating zero-filled extensions and only a partial tail on shrink.
    // Only one format-sized chunk is allocated at a time.
    #[allow(clippy::cast_possible_truncation)]
    pub fn resize(&mut self, size: u64) -> io::Result<()> {
        if size > i64::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file too large",
            ));
        }
        if size == self.size {
            return Ok(());
        }
        if size > self.size {
            let zeros = vec![0; CHUNK_PLAINTEXT_SIZE];
            while self.size < size {
                let count = (size - self.size).min(CHUNK_PLAINTEXT_SIZE as u64) as usize;
                self.write(self.size, &zeros[..count])?;
            }
            return Ok(());
        }
        self.ensure_stage()?;
        let tail = size / CHUNK_PLAINTEXT_SIZE as u64;
        let within = (size % CHUNK_PLAINTEXT_SIZE as u64) as usize;
        if self
            .dirty_chunk
            .as_ref()
            .is_some_and(|(index, _)| *index > tail || (*index == tail && within == 0))
        {
            self.dirty_chunk = None;
        }
        if within > 0 {
            let mut bytes = self.load(tail)?;
            if self
                .dirty_chunk
                .as_ref()
                .is_some_and(|(chunk, _)| *chunk == tail)
            {
                self.dirty_chunk = None;
            }
            self.flush_chunk()?;
            bytes.truncate(within);
            self.dirty_chunk = Some((tail, bytes));
        } else {
            self.flush_chunk()?;
        }
        self.size = size;
        self.flush_chunk()?;
        let end = self.offset(tail)
            + if within == 0 {
                0
            } else {
                (within + self.overhead()) as u64
            };
        self.stage
            .as_ref()
            .ok_or_else(|| io::Error::other("missing edit stage"))?
            .file
            .set_len(end)?;
        self.dirty = true;
        Ok(())
    }

    /// Apply metadata changes initiated by this mount without treating them as
    /// external content conflicts on the next commit.
    pub fn set_times(
        &mut self,
        accessed: Option<std::time::SystemTime>,
        modified: Option<std::time::SystemTime>,
    ) -> io::Result<()> {
        let actual = Identity::of(&self.reader.file.metadata()?)?;
        if self
            .expected
            .as_ref()
            .is_some_and(|expected| *expected != actual)
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "file changed before timestamp update",
            ));
        }
        let mut times = fs::FileTimes::new();
        if let Some(time) = accessed {
            times = times.set_accessed(time);
        }
        if let Some(time) = modified {
            times = times.set_modified(time);
        }
        self.reader.file.set_times(times)?;
        if self.expected.is_some() {
            self.expected = Some(Identity::of(&self.reader.file.metadata()?)?);
        }
        Ok(())
    }

    /// Copy the current ciphertext to an independent recovery location.
    pub fn copy_ciphertext(&mut self, destination: &Path) -> io::Result<()> {
        self.flush_chunk()?;
        let source = self
            .stage
            .as_mut()
            .map_or(&mut self.reader.file, |stage| &mut stage.file);
        let (file, copied) = clone_ciphertext(source, destination)?;
        self.stats.copied_ciphertext_bytes += copied;
        file.sync_all()
    }

    /// Commit with conflict detection; failed commits retain the complete stage.
    pub fn commit(&mut self, destination: &Path, vault_root: &Path) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let actual = match fs::metadata(destination) {
            Ok(metadata) => Some(Identity::of(&metadata)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if actual != self.expected {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "file changed since editor opened",
            ));
        }
        self.flush_chunk()?;
        let stage = self
            .stage
            .as_mut()
            .ok_or_else(|| io::Error::other("missing edit stage"))?;
        stage.file.sync_all()?;
        let parent = destination
            .parent()
            .ok_or_else(|| io::Error::other("missing destination parent"))?;
        let candidate = tempfile::tempdir_in(parent)?;
        let candidate_path = candidate.path().join("content");
        let (published, copied) = clone_ciphertext(&mut stage.file, &candidate_path)?;
        self.stats.copied_ciphertext_bytes += copied;
        published.sync_all()?;
        fs::rename(&candidate_path, destination)?;
        self.expected = Some(Identity::of(&published.metadata()?)?);
        crate::fs::durability::sync_directory_chain(parent, vault_root)?;
        self.reader.file = published;
        self.reader.plaintext_size = self.size;
        self.reader.chunk_cache.clear();
        destination.clone_into(&mut self.reader.decryptor.path);
        self.stage = None;
        self.dirty = false;
        Ok(())
    }
}

pub(crate) fn clone_ciphertext(source: &mut File, destination: &Path) -> io::Result<(File, u64)> {
    #[cfg(target_os = "macos")]
    if rustix::fs::fclonefileat(
        &*source,
        rustix::fs::CWD,
        destination,
        rustix::fs::CloneFlags::empty(),
    )
    .is_ok()
    {
        return Ok((
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(destination)?,
            0,
        ));
    }
    let mut target = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(destination)?;
    #[cfg(target_os = "linux")]
    if rustix::fs::ioctl_ficlone(&target, &*source).is_ok() {
        return Ok((target, 0));
    }
    source.seek(SeekFrom::Start(0))?;
    let copied = io::copy(source, &mut target)?;
    Ok((target, copied))
}

impl crate::fs::streaming::ChunkDecryptor {
    fn encrypt_chunk(&self, chunk: u64, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        use aes_gcm::{
            Aes256Gcm, KeyInit,
            aead::{Aead, Payload},
        };
        use rand::RngCore;
        match self.cipher_combo {
            CipherCombo::SivGcm => {
                let mut nonce = [0u8; 12];
                rand::rng().fill_bytes(&mut nonce);
                let mut aad = Vec::with_capacity(20);
                aad.extend_from_slice(&chunk.to_be_bytes());
                aad.extend_from_slice(&self.header_nonce);
                let cipher = Aes256Gcm::new_from_slice(&*self.content_key)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                let data = cipher
                    .encrypt(
                        aes_gcm::Nonce::from_slice(&nonce),
                        Payload {
                            msg: plaintext,
                            aad: &aad,
                        },
                    )
                    .map_err(|error| io::Error::other(error.to_string()))?;
                let mut encrypted = nonce.to_vec();
                encrypted.extend_from_slice(&data);
                Ok(encrypted)
            }
            CipherCombo::SivCtrMac => {
                use aes::cipher::{KeyIvInit, StreamCipher};
                let mut nonce = [0u8; 16];
                rand::rng().fill_bytes(&mut nonce);
                let mut data = plaintext.to_vec();
                let mut cipher = crate::fs::streaming::Aes256Ctr::new(
                    (&*self.content_key).into(),
                    (&nonce).into(),
                );
                cipher.apply_keystream(&mut data);
                let mac = self
                    .mac_key
                    .as_ref()
                    .ok_or_else(|| io::Error::other("missing MAC key"))?;
                let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, mac);
                let mut context = ring::hmac::Context::with_key(&key);
                context.update(&self.header_nonce);
                context.update(&chunk.to_be_bytes());
                context.update(&nonce);
                context.update(&data);
                let tag = context.sign();
                let mut encrypted = nonce.to_vec();
                encrypted.extend_from_slice(&data);
                encrypted.extend_from_slice(tag.as_ref());
                Ok(encrypted)
            }
        }
    }
}
