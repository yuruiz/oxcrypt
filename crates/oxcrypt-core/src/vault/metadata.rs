//! Confined access to local vault metadata before key authentication.
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Validate portable relative components before performing any filesystem I/O.
pub(crate) fn valid_relative_path(path: &str) -> bool {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .chars()
            .any(|character| character.is_control() || ":*?\"<>|".contains(character))
    {
        return false;
    }
    let mut components = 0;
    for component in path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." || component.ends_with(['.', ' ']) {
            return false;
        }
        let base = component
            .split('.')
            .next()
            .unwrap_or_default()
            .trim_matches(' ')
            .to_ascii_uppercase();
        if matches!(
            base.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) {
            return false;
        }
        if let Some(suffix) = base
            .strip_prefix("COM")
            .or_else(|| base.strip_prefix("LPT"))
            && matches!(
                suffix,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        {
            return false;
        }
        components += 1;
    }
    components > 0
}

/// Resolve metadata without following untrusted symlinks in the vault tree.
/// The root itself is selected by the caller and may have a trusted alias.
pub(crate) fn resolve_vault_file(root: &Path, relative: &Path) -> io::Result<PathBuf> {
    let text = relative
        .to_str()
        .filter(|path| valid_relative_path(path))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "vault metadata path must be a portable relative path",
            )
        })?;
    let mut current = fs::canonicalize(root)?;
    let mut components = text
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .peekable();
    while let Some(component) = components.next() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vault metadata path must not contain symlinks",
            ));
        }
        if components.peek().is_some() {
            if !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "metadata parent is not a directory",
                ));
            }
        } else if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vault metadata must be a regular file",
            ));
        }
    }
    Ok(current)
}

pub(crate) fn read_vault_file(root: &Path, relative: &Path) -> io::Result<String> {
    fs::read_to_string(resolve_vault_file(root, relative)?)
}
