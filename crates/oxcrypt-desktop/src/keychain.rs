//! Opt-in vault credentials stored in the OS keychain, keyed by the app's vault ID.

use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
const SERVICE: &str = "org.oxcrypt.desktop.vault-password";
#[cfg(target_os = "macos")]
const ITEM_NOT_FOUND: i32 = -25300;

#[cfg(target_os = "macos")]
pub fn load(account: &str) -> Result<Option<Zeroizing<String>>, String> {
    use security_framework::passwords::{PasswordOptions, generic_password};
    match generic_password(PasswordOptions::new_generic_password(SERVICE, account)) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            let text =
                std::str::from_utf8(&bytes).map_err(|_| "Saved password is not valid UTF-8")?;
            Ok(Some(Zeroizing::new(text.to_owned())))
        }
        Err(error) if error.code() == ITEM_NOT_FOUND => Ok(None),
        Err(error) => Err(format!(
            "Keychain access failed (OSStatus {})",
            error.code()
        )),
    }
}

#[cfg(target_os = "macos")]
pub fn store(account: &str, password: &str) -> Result<(), String> {
    security_framework::passwords::set_generic_password(SERVICE, account, password.as_bytes())
        .map_err(|error| format!("Could not save password (OSStatus {})", error.code()))
}

#[cfg(target_os = "macos")]
pub fn forget(account: &str) -> Result<(), String> {
    match security_framework::passwords::delete_generic_password(SERVICE, account) {
        Ok(()) => Ok(()),
        Err(error) if error.code() == ITEM_NOT_FOUND => Ok(()),
        Err(error) => Err(format!(
            "Could not forget password (OSStatus {})",
            error.code()
        )),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn load(_account: &str) -> Result<Option<Zeroizing<String>>, String> {
    Ok(None)
}

#[cfg(not(target_os = "macos"))]
pub fn store(_account: &str, _password: &str) -> Result<(), String> {
    Err("System Keychain is only available on macOS".to_owned())
}

#[cfg(not(target_os = "macos"))]
pub fn forget(_account: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use crate::keychain::{forget, load, store};

    #[test]
    #[ignore = "requires an unlocked macOS login keychain"]
    fn keychain_roundtrip_update_and_forget() {
        struct TestAccount(String);
        impl Drop for TestAccount {
            fn drop(&mut self) {
                let _ = forget(&self.0);
            }
        }
        let account = TestAccount(format!("test-{}", uuid::Uuid::new_v4()));
        assert!(load(&account.0).unwrap().is_none());
        store(&account.0, "test-password-one").unwrap();
        assert_eq!(
            load(&account.0).unwrap().unwrap().as_str(),
            "test-password-one"
        );
        store(&account.0, "test-password-two").unwrap();
        assert_eq!(
            load(&account.0).unwrap().unwrap().as_str(),
            "test-password-two"
        );
        forget(&account.0).unwrap();
        assert!(load(&account.0).unwrap().is_none());
        forget(&account.0).unwrap();
    }
}
