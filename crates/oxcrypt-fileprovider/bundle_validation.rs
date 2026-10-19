//! Structural checks for a prebuilt host application and its extension.
use std::path::Path;

pub(crate) fn complete_bundle(bundle: &Path) -> bool {
    [
        "Contents/Info.plist",
        "Contents/MacOS/OxCryptFileProvider",
        "Contents/PlugIns/OxCryptFileProviderExtension.appex/Contents/Info.plist",
        "Contents/PlugIns/OxCryptFileProviderExtension.appex/Contents/MacOS/OxCryptFileProviderExtension",
    ].iter().all(|relative| std::fs::metadata(bundle.join(relative))
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0))
}

#[cfg(test)]
mod tests {
    use crate::bundle_validation::complete_bundle;
    #[test]
    fn empty_and_partial_bundles_are_not_installable() {
        let temporary = tempfile::tempdir().unwrap();
        assert!(!complete_bundle(temporary.path()));
        for relative in [
            "Contents/Info.plist",
            "Contents/MacOS/OxCryptFileProvider",
            "Contents/PlugIns/OxCryptFileProviderExtension.appex/Contents/Info.plist",
        ] {
            let path = temporary.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"test fixture").unwrap();
        }
        assert!(!complete_bundle(temporary.path()));
        let executable = temporary.path().join("Contents/PlugIns/OxCryptFileProviderExtension.appex/Contents/MacOS/OxCryptFileProviderExtension");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, b"").unwrap();
        assert!(!complete_bundle(temporary.path()));
        std::fs::write(executable, b"test executable fixture").unwrap();
        assert!(complete_bundle(temporary.path()));
    }
}
