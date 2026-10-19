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
    // Owns the encrypted stage until commit or drop.
    #[allow(dead_code)]
    directory: tempfile::TempDir,
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
    pending_accessed: Option<std::time::SystemTime>,
    pending_modified: Option<std::time::SystemTime>,
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
            pending_accessed: None,
            pending_modified: None,
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
            directory,
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
    /// Whether content or metadata still need a durable commit.
    pub fn is_dirty(&self) -> bool {
        self.dirty || self.pending_accessed.is_some() || self.pending_modified.is_some()
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
            self.stage = Some(Stage { directory, file });
        }
        Ok(())
    }
    // Chunk offsets and lengths are bounded by the 32 KiB format limit.
    #[allow(clippy::cast_possible_truncation)]
    fn load(&mut self, chunk: u64) -> io::Result<std::sync::Arc<Zeroizing<Vec<u8>>>> {
        if let Some((number, data)) = &self.dirty_chunk
            && *number == chunk
        {
            return Ok(std::sync::Arc::new(data.clone()));
        }
        if let Some(data) = self.reader.chunk_cache.get(&chunk) {
            return Ok(std::sync::Arc::clone(data));
        }
        let begin = chunk * CHUNK_PLAINTEXT_SIZE as u64;
        if begin >= self.size {
            return Ok(std::sync::Arc::new(Zeroizing::new(Vec::new())));
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
        let data = std::sync::Arc::new(Zeroizing::new(data));
        self.reader
            .chunk_cache
            .put(chunk, std::sync::Arc::clone(&data));
        Ok(data)
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
            self.reader
                .chunk_cache
                .put(*chunk, std::sync::Arc::new(plaintext.clone()));
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
        let mut position = offset;
        let mut written = 0;
        while written < data.len() {
            let chunk = position / CHUNK_PLAINTEXT_SIZE as u64;
            let within = (position % CHUNK_PLAINTEXT_SIZE as u64) as usize;
            let count = (CHUNK_PLAINTEXT_SIZE - within).min(data.len() - written);
            let step = (|| {
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
                    (*self.load(chunk)?).clone()
                };
                if bytes.get(within..within + count) == Some(&data[written..written + count]) {
                    return Ok::<(), io::Error>(());
                }
                self.ensure_stage()?;
                let length = bytes.len().max(within + count);
                bytes.resize(length, 0);
                bytes[within..within + count].copy_from_slice(&data[written..written + count]);
                self.reader.chunk_cache.pop(&chunk);
                self.dirty_chunk = Some((chunk, bytes));
                self.size = self.size.max(position + count as u64);
                self.pending_modified = Some(std::time::SystemTime::now());
                self.dirty = true;
                Ok(())
            })();
            if let Err(error) = step {
                return if written == 0 {
                    Err(error)
                } else {
                    Ok(written)
                };
            }
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
            if size == 0 {
                let length = self
                    .stage
                    .as_ref()
                    .map_or(&self.reader.file, |stage| &stage.file)
                    .metadata()?
                    .len();
                let header = self.offset(0);
                if length > header {
                    self.ensure_stage()?;
                    self.stage
                        .as_ref()
                        .ok_or_else(|| io::Error::other("missing edit stage"))?
                        .file
                        .set_len(header)?;
                    self.reader.chunk_cache.clear();
                    self.dirty = true;
                }
            }
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
            let mut bytes = (*self.load(tail)?).clone();
            if self
                .dirty_chunk
                .as_ref()
                .is_some_and(|(chunk, _)| *chunk == tail)
            {
                self.dirty_chunk = None;
            }
            self.flush_chunk()?;
            bytes.truncate(within);
            self.reader.chunk_cache.pop(&tail);
            self.dirty_chunk = Some((tail, bytes));
        } else {
            self.flush_chunk()?;
        }
        let obsolete: Vec<_> = self
            .reader
            .chunk_cache
            .iter()
            .filter(|(number, _)| **number >= tail)
            .map(|(number, _)| *number)
            .collect();
        for number in obsolete {
            self.reader.chunk_cache.pop(&number);
        }
        self.size = size;
        self.pending_modified = Some(std::time::SystemTime::now());
        self.dirty = true;
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

    /// Adopt the backing inode produced by our own successful namespace move.
    /// The authenticated header and original ciphertext length must be unchanged.
    pub fn follow_rename(&mut self, destination: &Path) -> io::Result<()> {
        let mut file = File::open(destination)?;
        let identity = Identity::of(&file.metadata()?)?;
        if self
            .expected
            .as_ref()
            .is_none_or(|expected| expected.length != identity.length)
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "renamed file length changed",
            ));
        }
        let header_len = usize::try_from(self.offset(0)).map_err(io::Error::other)?;
        let mut original = vec![0; header_len];
        let mut renamed = vec![0; header_len];
        self.reader.file.seek(SeekFrom::Start(0))?;
        self.reader.file.read_exact(&mut original)?;
        file.read_exact(&mut renamed)?;
        if original != renamed {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "renamed file identity changed",
            ));
        }
        self.reader.file = file;
        self.reader.chunk_cache.clear();
        self.expected = Some(identity);
        destination.clone_into(&mut self.reader.decryptor.path);
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
        if let Some(time) = accessed {
            self.pending_accessed = Some(time);
        }
        if let Some(time) = modified {
            self.pending_modified = Some(time);
        }
        if self.expected.is_some() {
            self.expected = Some(Identity::of(&self.reader.file.metadata()?)?);
        }
        Ok(())
    }

    /// Copy the current ciphertext to an independent recovery location.
    pub fn copy_ciphertext(&mut self, destination: &Path) -> io::Result<()> {
        // Recovery must work even when the vault stage can no longer be written.
        // Copy its ciphertext first, then seal the remaining dirty chunk locally.
        let source = self
            .stage
            .as_mut()
            .map_or(&mut self.reader.file, |stage| &mut stage.file);
        let (mut file, copied) = clone_ciphertext(source, destination)?;
        self.stats.copied_ciphertext_bytes += copied;
        if let Some((chunk, bytes)) = &self.dirty_chunk {
            let encrypted = self.reader.decryptor.encrypt_chunk(*chunk, bytes)?;
            file.seek(SeekFrom::Start(self.offset(*chunk)))?;
            file.write_all(&encrypted)?;
            self.stats.encrypted_chunks += 1;
        }
        Self::fix_length(&file, self.size, self.cipher())?;
        file.sync_all()
    }

    fn fix_length(file: &File, size: u64, cipher: CipherCombo) -> io::Result<()> {
        if crate::fs::streaming::encrypted_to_plaintext_size_for_cipher(
            file.metadata()?.len(),
            cipher,
        ) != Some(size)
        {
            let chunks = size / CHUNK_PLAINTEXT_SIZE as u64;
            let tail = size % CHUNK_PLAINTEXT_SIZE as u64;
            let overhead = if cipher == CipherCombo::SivGcm {
                28
            } else {
                48
            };
            let length = chunk_to_encrypted_offset_for_cipher(chunks, cipher)
                + if tail == 0 { 0 } else { tail + overhead };
            file.set_len(length)?;
        }
        Ok(())
    }

    /// Commit with conflict detection; failed commits retain the complete stage.
    pub fn commit(&mut self, destination: &Path, vault_root: &Path) -> io::Result<()> {
        if !self.is_dirty() {
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
        if !self.dirty {
            // Metadata-only edits still require fsync, without rewriting content.
            self.reader.file.sync_all()?;
            self.pending_accessed = None;
            self.pending_modified = None;
            return Ok(());
        }
        self.flush_chunk()?;
        let cipher = self.cipher();
        let stage = self
            .stage
            .as_mut()
            .ok_or_else(|| io::Error::other("missing edit stage"))?;
        Self::fix_length(&stage.file, self.size, cipher)?;
        stage.file.sync_all()?;
        let parent = destination
            .parent()
            .ok_or_else(|| io::Error::other("missing destination parent"))?;
        let candidate = tempfile::tempdir_in(parent)?;
        let candidate_path = candidate.path().join("content");
        let (published, copied) = clone_ciphertext(&mut stage.file, &candidate_path)?;
        self.stats.copied_ciphertext_bytes += copied;
        // Apply times after all ciphertext writes and copies: both operations
        // can update mtime, and a copy fallback need not preserve source times.
        let mut times = fs::FileTimes::new();
        if let Some(time) = self.pending_accessed {
            times = times.set_accessed(time);
        }
        if let Some(time) = self.pending_modified {
            times = times.set_modified(time);
        }
        published.set_times(times)?;
        published.sync_all()?;
        fs::rename(&candidate_path, destination)?;
        self.expected = Some(Identity::of(&published.metadata()?)?);
        crate::fs::durability::sync_directory_chain(parent, vault_root)?;
        self.reader.file = published;
        self.reader.plaintext_size = self.size;
        destination.clone_into(&mut self.reader.decryptor.path);
        self.stage = None;
        self.pending_accessed = None;
        self.pending_modified = None;
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

#[cfg(test)]
mod recovery_tests {
    use crate::fs::streaming::editor::*;
    #[test]
    fn recovery_can_seal_dirty_data_when_vault_stage_is_unwritable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original");
        let recovery = directory.path().join("recovered");
        let key = MasterKey::random().unwrap();
        let cipher = CipherCombo::SivGcm;
        let original = cipher.encrypt_file(b"original", &key).unwrap();
        fs::write(&path, &original).unwrap();
        let mut editor = VaultFileEditor::open(&path, &key, cipher, directory.path()).unwrap();
        editor.write(0, b"UPDATED!").unwrap();
        let stage = editor.stage.as_mut().unwrap();
        stage.file = File::open(stage.directory.path().join("content")).unwrap();
        assert!(editor.commit(&path, directory.path()).is_err());
        assert!(editor.is_dirty());
        editor.copy_ciphertext(&recovery).unwrap();
        assert_eq!(
            cipher
                .decrypt_file(&fs::read(recovery).unwrap(), &key)
                .unwrap()
                .content,
            b"UPDATED!"
        );
        assert_eq!(fs::read(path).unwrap(), original);
    }
}
