use anyhow::Result;
use clap::Args as ClapArgs;
use oxcrypt_core::vault::VaultOperations;
use std::path::PathBuf;

#[derive(ClapArgs)]
pub struct Args {
    /// Encrypted recovery directory reported by the mount
    pub recovery_directory: PathBuf,
    /// New local output file (must not exist)
    pub output: PathBuf,
}

pub fn execute(ops: &VaultOperations, args: &Args) -> Result<()> {
    let metadata = oxcrypt_core::fs::recovery::export(
        &args.recovery_directory,
        ops.master_key(),
        &args.output,
    )?;
    println!(
        "Recovered {} to {}. Encrypted recovery copy retained at {}.",
        metadata.filename,
        args.output.display(),
        args.recovery_directory.display()
    );
    Ok(())
}
