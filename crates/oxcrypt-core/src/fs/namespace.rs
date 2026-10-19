//! Atomic publication of a complete encrypted directory entry.
use std::{fs, io, path::Path};

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Kind {
    File,
    Directory,
    Symlink,
}

/// A shortened file may have a reserved container before its contents are
/// published, but it must never reuse directory or symlink markers.
pub(crate) fn check_file_container(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(metadata) if !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "file container has an incompatible type",
            ));
        }
        Ok(_) => {}
    }
    for marker in ["dir.c9r", "symlink.c9r"] {
        match fs::symlink_metadata(path.join(marker)) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "destination is a directory or symlink",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) fn inspect(path: &Path) -> io::Result<Kind> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_file() {
        return Ok(Kind::File);
    }
    if metadata.is_dir() {
        let mut found = None;
        for (name, kind) in [
            ("contents.c9r", Kind::File),
            ("dir.c9r", Kind::Directory),
            ("symlink.c9r", Kind::Symlink),
        ] {
            if path.join(name).try_exists()? {
                if found.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ambiguous encrypted entry",
                    ));
                }
                found = Some(kind);
            }
        }
        if let Some(kind) = found {
            return Ok(kind);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid encrypted entry",
    ))
}

fn payload(path: &Path, kind: Kind) -> std::path::PathBuf {
    if path.is_file() {
        path.to_path_buf()
    } else {
        path.join(match kind {
            Kind::File => "contents.c9r",
            Kind::Directory => "dir.c9r",
            Kind::Symlink => "symlink.c9r",
        })
    }
}

fn remove_entry(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path)?.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

/// Never remove the destination before publishing its replacement. Where the
/// physical representation changes, stage a complete entry and exchange it.
/// A crash after publication can leave a duplicate source, never a missing target.
pub(crate) fn replace(
    source: &Path,
    target: &Path,
    shortened_name: Option<&str>,
    root: &Path,
) -> io::Result<()> {
    let kind = inspect(source)?;
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::other("missing target parent"))?;
    fs::create_dir_all(parent)?;
    let source_parent = source
        .parent()
        .ok_or_else(|| io::Error::other("missing source parent"))?;
    if kind == Kind::File
        && source.is_file()
        && shortened_name.is_none()
        && (!target.try_exists()? || target.is_file())
    {
        fs::File::open(source)?.sync_all()?;
        fs::rename(source, target)?;
        crate::fs::durability::sync_directory_chain(parent, root)?;
        crate::fs::durability::sync_directory_chain(source_parent, root)?;
        return Ok(());
    }
    let stage = tempfile::tempdir_in(parent)?;
    let entry = stage.path().join("entry");
    if kind != Kind::File || shortened_name.is_some() {
        fs::create_dir(&entry)?;
    }
    let content = if entry.is_dir() {
        entry.join(match kind {
            Kind::File => "contents.c9r",
            Kind::Directory => "dir.c9r",
            Kind::Symlink => "symlink.c9r",
        })
    } else {
        entry.clone()
    };
    // An interrupted rename may retain both names. Independent COW/ciphertext
    // copies prevent a later in-place writer from changing both aliases.
    let source_payload = payload(source, kind);
    #[cfg(feature = "async")]
    crate::fs::streaming::editor::clone_ciphertext(
        &mut fs::File::open(&source_payload)?,
        &content,
    )?;
    #[cfg(not(feature = "async"))]
    fs::copy(&source_payload, &content)?;
    fs::File::open(&content)?.sync_all()?;
    if let Some(name) = shortened_name {
        let name_path = entry.join("name.c9s");
        fs::write(&name_path, name)?;
        fs::File::open(name_path)?.sync_all()?;
    }
    if entry.is_dir() {
        crate::fs::durability::sync_directory_chain(&entry, root)?;
    }
    if target.try_exists()? {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &entry,
            rustix::fs::CWD,
            target,
            rustix::fs::RenameFlags::EXCHANGE,
        )?;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic entry exchange is unavailable",
        ));
    } else {
        fs::rename(&entry, target)?;
    }
    crate::fs::durability::sync_directory_chain(parent, root)?;
    if let Err(error) = remove_entry(source) {
        tracing::warn!(?source, %error, "Replacement committed; source cleanup must be retried");
    }
    crate::fs::durability::sync_directory_chain(source_parent, root)?;
    Ok(())
}

/// Exchange existing payloads atomically, preserving open-file identity.
pub(crate) fn exchange(first: &Path, second: &Path, root: &Path) -> io::Result<()> {
    fs::File::open(first)?.sync_all()?;
    fs::File::open(second)?.sync_all()?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        first,
        rustix::fs::CWD,
        second,
        rustix::fs::RenameFlags::EXCHANGE,
    )?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic exchange unavailable",
    ));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        crate::fs::durability::sync_directory_chain(
            first
                .parent()
                .ok_or_else(|| io::Error::other("missing parent"))?,
            root,
        )?;
        crate::fs::durability::sync_directory_chain(
            second
                .parent()
                .ok_or_else(|| io::Error::other("missing parent"))?,
            root,
        )
    }
}
