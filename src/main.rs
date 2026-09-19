use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use localcert::{ca, leaf, names::output_stem};

#[derive(Parser)]
#[command(
    name = "localcert",
    about = "Local dev TLS certs, zero OpenSSL — a mkcert alternative"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate the local CA (once). Refuses to overwrite an existing one.
    Init {
        #[arg(long)]
        ca_dir: Option<PathBuf>,
    },
    /// Issue a leaf certificate for one or more hostnames/IPs, signed by
    /// the local CA. Writes `<name>.pem` / `<name>-key.pem` in the current
    /// directory (or `<name>+N.pem` for multiple names, matching mkcert).
    Cert {
        names: Vec<String>,
        #[arg(long)]
        ca_dir: Option<PathBuf>,
    },
    /// Print (does not run) the OS-specific command to trust the local CA
    /// system-wide. Never escalates privileges on its own — trusting a
    /// root CA system-wide is exactly the kind of action that should
    /// require you to actually read the command first.
    Install {
        #[arg(long)]
        ca_dir: Option<PathBuf>,
    },
}

fn default_ca_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("localcert")
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { ca_dir } => {
            let dir = ca_dir.unwrap_or_else(default_ca_dir);
            let cert_path = dir.join("rootCA.pem");
            let key_path = dir.join("rootCA-key.pem");
            if cert_path.exists() {
                anyhow::bail!(
                    "{} already exists — refusing to overwrite an existing CA \
                     (every certificate you've already issued would stop being trusted)",
                    cert_path.display()
                );
            }
            fs::create_dir_all(&dir)?;
            let generated = ca::generate_ca()?;
            fs::write(&cert_path, &generated.cert_pem)?;
            fs::write(&key_path, &generated.key_pem)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
            }
            println!("CA created:");
            println!("  {}", cert_path.display());
            println!("  {} (keep this private)", key_path.display());
            println!(
                "\nRun `localcert install` next to trust it, then `localcert cert <hostnames...>`."
            );
        }
        Command::Cert { names, ca_dir } => {
            if names.is_empty() {
                anyhow::bail!("give at least one hostname or IP, e.g. `localcert cert myapp.test localhost 127.0.0.1`");
            }
            let dir = ca_dir.unwrap_or_else(default_ca_dir);
            let loaded = load_ca(&dir)?;
            let issued = leaf::issue_leaf(&loaded, &names)?;

            let stem = output_stem(&names);
            let cert_path = PathBuf::from(format!("{stem}.pem"));
            let key_path = PathBuf::from(format!("{stem}-key.pem"));
            fs::write(&cert_path, &issued.cert_pem)?;
            fs::write(&key_path, &issued.key_pem)?;
            println!(
                "{} -> {}, {}",
                names.join(", "),
                cert_path.display(),
                key_path.display()
            );
        }
        Command::Install { ca_dir } => {
            let dir = ca_dir.unwrap_or_else(default_ca_dir);
            let cert_path = dir.join("rootCA.pem");
            if !cert_path.exists() {
                anyhow::bail!(
                    "no CA at {} yet — run `localcert init` first",
                    cert_path.display()
                );
            }
            print_install_instructions(&cert_path);
        }
    }
    Ok(())
}

/// Loads the CA's cert+key back from disk into the same in-memory shape
/// `issue_leaf` needs. `rcgen::CertificateParams` doesn't round-trip
/// through PEM on its own (it's the *input* to signing, not something
/// parsed back out of an issued certificate), so this reconstructs a
/// self-signed-equivalent `Ca` from the saved key pair — sufficient for
/// `Issuer::new`, which only needs the CA's distinguished name and key.
fn load_ca(dir: &Path) -> anyhow::Result<ca::Ca> {
    let cert_path = dir.join("rootCA.pem");
    let key_path = dir.join("rootCA-key.pem");
    let cert_pem = fs::read_to_string(&cert_path).map_err(|e| {
        anyhow::anyhow!(
            "reading {}: {e} (run `localcert init` first)",
            cert_path.display()
        )
    })?;
    let key_pem = fs::read_to_string(&key_path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", key_path.display()))?;
    ca::load_ca(&cert_pem, &key_pem)
}

fn print_install_instructions(cert_path: &std::path::Path) {
    let path = cert_path.display();
    println!("This never runs a command for you — trusting a root CA system-wide is worth reading first.\n");
    #[cfg(target_os = "linux")]
    println!(
        "Linux (Debian/Ubuntu/Arch):\n  sudo cp {path} /usr/local/share/ca-certificates/localcert-root.crt\n  sudo update-ca-certificates\n\nFedora/RHEL:\n  sudo cp {path} /etc/pki/ca-trust/source/anchors/localcert-root.pem\n  sudo update-ca-trust\n\nFirefox uses its own store, not the OS one — import {path} under Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import."
    );
    #[cfg(target_os = "macos")]
    println!(
        "macOS:\n  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {path}"
    );
    #[cfg(target_os = "windows")]
    println!("Windows (PowerShell, as Administrator):\n  Import-Certificate -FilePath \"{path}\" -CertStoreLocation Cert:\\LocalMachine\\Root");
}
