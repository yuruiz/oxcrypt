//! Chunked WebDAV file handles with atomic encrypted write-back.
use crate::{
    error::{io_error_to_fs_error, write_error_to_fs_error},
    metadata::CryptomatorMetaData,
};
use bytes::Bytes;
use dav_server::fs::{DavFile, DavMetaData, FsError, FsFuture};
use oxcrypt_core::{fs::streaming::VaultFileReader, vault::VaultOperationsAsync};
use oxcrypt_mount::{EditBuffer, HandleTable, VaultStats, moka_cache::SyncTtlCache};
use std::{io::SeekFrom, sync::Arc};

type MetadataCache = SyncTtlCache<String, CryptomatorMetaData>;
pub(crate) type WriteBufferTable = HandleTable<String, Arc<EditBuffer>>;

#[derive(Debug)]
pub enum CryptomatorFile {
    Reader {
        reader: Box<VaultFileReader>,
        filename: String,
        position: u64,
        stats: Arc<VaultStats>,
    },
    Writer(WriterHandle),
}

pub struct WriterHandle {
    buffer: Arc<EditBuffer>,
    ops: Arc<VaultOperationsAsync>,
    position: u64,
    filename: String,
    vault_path: String,
    cache: Arc<MetadataCache>,
    stats: Arc<VaultStats>,
    pending: Arc<WriteBufferTable>,
    flush_lock: Arc<tokio::sync::Mutex<()>>,
}
impl std::fmt::Debug for WriterHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriterHandle")
            .field("filename", &self.filename)
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl CryptomatorFile {
    pub fn reader(reader: VaultFileReader, filename: String, stats: Arc<VaultStats>) -> Self {
        stats.record_file_open();
        Self::Reader {
            reader: Box::new(reader),
            filename,
            position: 0,
            stats,
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn writer(
        buffer: Arc<EditBuffer>,
        filename: String,
        ops: Arc<VaultOperationsAsync>,
        vault_path: String,
        cache: Arc<MetadataCache>,
        stats: Arc<VaultStats>,
        pending: Arc<WriteBufferTable>,
        flush_lock: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        stats.record_file_open();
        Self::Writer(WriterHandle {
            buffer,
            ops,
            position: 0,
            filename,
            vault_path,
            cache,
            stats,
            pending,
            flush_lock,
        })
    }
    fn size(&self) -> u64 {
        match self {
            Self::Reader { reader, .. } => reader.plaintext_size(),
            Self::Writer(handle) => handle.buffer.len(),
        }
    }
}

impl DavFile for CryptomatorFile {
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        Box::pin(async move {
            let name = match self {
                Self::Reader { filename, .. } => filename.clone(),
                Self::Writer(handle) => handle.filename.clone(),
            };
            Ok(
                Box::new(CryptomatorMetaData::file_with_size(name, self.size()))
                    as Box<dyn DavMetaData>,
            )
        })
    }
    fn read_bytes(&mut self, count: usize) -> FsFuture<'_, Bytes> {
        Box::pin(async move {
            match self {
                Self::Reader {
                    reader,
                    position,
                    stats,
                    ..
                } => {
                    let data = reader
                        .read_range(*position, count)
                        .await
                        .map_err(|_| FsError::GeneralFailure)?;
                    *position += data.len() as u64;
                    stats.record_read(data.len() as u64);
                    Ok(Bytes::from(data))
                }
                Self::Writer(handle) => {
                    let editor = Arc::clone(&handle.buffer);
                    let position = handle.position;
                    let data = tokio::task::spawn_blocking(move || editor.read(position, count))
                        .await
                        .map_err(|_| FsError::GeneralFailure)?
                        .map_err(|error| io_error_to_fs_error(&error))?;
                    handle.position += data.len() as u64;
                    Ok(Bytes::from(data))
                }
            }
        })
    }
    fn write_bytes(&mut self, bytes: Bytes) -> FsFuture<'_, ()> {
        Box::pin(async move {
            let Self::Writer(handle) = self else {
                return Err(FsError::Forbidden);
            };
            let editor = Arc::clone(&handle.buffer);
            let position = handle.position;
            let written = tokio::task::spawn_blocking(move || {
                let mut written = 0;
                while written < bytes.len() {
                    let count = editor.write(position + written as u64, &bytes[written..])?;
                    if count == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "short encrypted write",
                        ));
                    }
                    written += count;
                }
                Ok::<usize, std::io::Error>(written)
            })
            .await
            .map_err(|_| FsError::GeneralFailure)?
            .map_err(|error| io_error_to_fs_error(&error))?;
            handle.position += written as u64;
            handle.stats.record_write(written as u64);
            Ok(())
        })
    }
    fn write_buf(&mut self, mut buffer: Box<dyn bytes::Buf + Send>) -> FsFuture<'_, ()> {
        Box::pin(async move {
            self.write_bytes(buffer.copy_to_bytes(buffer.remaining()))
                .await
        })
    }
    fn seek(&mut self, target: SeekFrom) -> FsFuture<'_, u64> {
        Box::pin(async move {
            let position = match self {
                Self::Reader { position, .. } => *position,
                Self::Writer(handle) => handle.position,
            };
            let target = match target {
                SeekFrom::Start(value) => Some(value),
                SeekFrom::Current(delta) => position.checked_add_signed(delta),
                SeekFrom::End(delta) => self.size().checked_add_signed(delta),
            }
            .filter(|value| i64::try_from(*value).is_ok())
            .ok_or(FsError::GeneralFailure)?;
            match self {
                Self::Reader { position, .. } => *position = target,
                Self::Writer(handle) => handle.position = target,
            }
            Ok(target)
        })
    }
    fn flush(&mut self) -> FsFuture<'_, ()> {
        Box::pin(async move {
            if let Self::Writer(handle) = self {
                let _guard = handle.flush_lock.lock().await;
                handle
                    .buffer
                    .commit(&handle.ops)
                    .await
                    .map_err(write_error_to_fs_error)?;
                handle.cache.invalidate(&handle.vault_path);
                handle.pending.retain(|path, editor| {
                    path != &handle.vault_path || !Arc::ptr_eq(editor, &handle.buffer)
                });
            }
            Ok(())
        })
    }
}

impl Drop for CryptomatorFile {
    fn drop(&mut self) {
        match self {
            Self::Reader { stats, .. } => stats.record_file_close(),
            Self::Writer(handle) => handle.stats.record_file_close(),
        }
    }
}
