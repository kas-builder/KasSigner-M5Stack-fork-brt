// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// KasSigner — Developer Signing Key Generator
// Generates a Schnorr keypair (secp256k1) for firmware signing.
//
// Usage: gen-keypair <output_dir-outside-repository>
//
// Creates:
//   release_signing_key.bin — 32-byte private key (KEEP SECRET, BACK UP OFFLINE)
//   release_pubkey.hex   — public key (safe to copy into release/)
//
// The private key is used by the production build to sign firmware metadata.
// The public key is embedded in the firmware and used at boot to verify signatures.
//
// WARNING: Losing the private key means you can NEVER sign firmware updates again.
//          Back it up to multiple secure offline locations.

use k256::{
    SecretKey,
    elliptic_curve::sec1::ToEncodedPoint,
};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

fn fail(message: &str) -> ! {
    eprintln!("  ERROR: {message}");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        fail("Usage: gen-keypair <output-directory-outside-repository>");
    }

    let output_dir = Path::new(&args[1]);
    if !output_dir.is_absolute() {
        fail("Output directory must be an absolute path outside the repository");
    }
    let repository = fs::canonicalize(env!("CARGO_MANIFEST_DIR"))
        .and_then(|path| path.parent().map(Path::to_path_buf).ok_or(io::ErrorKind::NotFound.into()))
        .unwrap_or_else(|_| fail("Could not determine repository path"));
    fs::create_dir_all(output_dir).unwrap_or_else(|e| fail(&format!("Could not create output directory: {e}")));
    let output_dir = fs::canonicalize(output_dir)
        .unwrap_or_else(|e| fail(&format!("Could not resolve output directory: {e}")));
    if output_dir.starts_with(&repository) {
        fail("Refusing to place signing material inside the repository");
    }

    println!("╔════════════════════════════════════════════════╗");
    println!("║  KasSigner — Developer Signing Key Generator   ║");
    println!("╚════════════════════════════════════════════════╝");
    println!();

    let key_path = output_dir.join("release_signing_key.bin");
    let pubkey_path = output_dir.join("release_pubkey.hex");

    // Check if key already exists — refuse to overwrite
    if key_path.exists() || pubkey_path.exists() {
        fail("Refusing to overwrite an existing private or public key file");
    }

    // Generate random private key
    let sk = SecretKey::random(&mut rand_core::OsRng);
    let sk_bytes = sk.to_bytes();

    // Derive public key (x-only, 32 bytes, BIP340-style)
    let pk_point = sk.public_key().to_projective();
    let pk_affine = k256::AffinePoint::from(pk_point);
    let encoded = pk_affine.to_encoded_point(true); // compressed: 02/03 || x
    let pk_x_bytes: [u8; 32] = {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&encoded.as_bytes()[1..33]);
        buf
    };

    // Save private key
    let mut private_options = fs::OpenOptions::new();
    private_options.write(true).create_new(true);
    #[cfg(unix)]
    private_options.mode(0o600);
    let mut key_file = private_options.open(&key_path).expect("Failed to create private key file");
    key_file.write_all(&sk_bytes).expect("Failed to write key");
    key_file.sync_all().expect("Failed to sync private key");
    #[cfg(unix)]
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .expect("Failed to restrict private key permissions");
    println!("  Private key saved: {}", key_path.display());
    println!("  !! BACK THIS UP TO MULTIPLE SECURE OFFLINE LOCATIONS !!");
    println!();

    let pk_hex: String = pk_x_bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let mut public_options = fs::OpenOptions::new();
    public_options.write(true).create_new(true);
    #[cfg(unix)]
    public_options.mode(0o644);
    let mut public_file = public_options.open(&pubkey_path).expect("Failed to create public key file");
    writeln!(public_file, "{pk_hex}").expect("Failed to write public key");

    println!("  Public key file: {}", pubkey_path.display());
    println!("  Public key (hex): {}", pk_hex);
    println!();
    println!("  Next steps:");
    println!("    1. Copy ONLY release_pubkey.hex to the repository's release directory");
    println!("    2. Keep release_signing_key.bin outside the repository and offline");
    println!("    3. Pass its absolute path explicitly with --key for production builds");
    println!();
    println!("  WARNING: Never send, upload, print, or commit release_signing_key.bin");
}
