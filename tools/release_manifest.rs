use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const FORMAT: &str = "kassigner-release-v1";
const REPOSITORY: &str = "kas-builder/KasSigner-M5Stack-fork-brt";
const BOARD: &str = "m5stack-cores3";
const PROFILE: &str = "production";
const ARTIFACT: &str = "kassigner-m5stack.bin";
const IMAGE_LAYOUT: &str = "merged-full-flash";
const FLASH_SIZE: &str = "16mb";
const FLASH_OFFSET: &str = "0x0";
const PARTITION_TABLE_OFFSET: usize = 0x8000;
const APP_OFFSET: usize = 0x10000;

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("ERROR: {message}");
    std::process::exit(1);
}

fn read_exact<const N: usize>(path: &Path, label: &str) -> [u8; N] {
    let data = fs::read(path).unwrap_or_else(|e| fail(format!("cannot read {label}: {e}")));
    data.try_into().unwrap_or_else(|data: Vec<u8>| {
        fail(format!(
            "{label} must be exactly {N} bytes; got {}",
            data.len()
        ))
    })
}

fn decode_hex<const N: usize>(text: &str, label: &str) -> [u8; N] {
    let text = text.trim();
    if text.len() != N * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        fail(format!(
            "{label} must be exactly {} hexadecimal characters",
            N * 2
        ));
    }
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .unwrap_or_else(|_| fail(format!("invalid {label}")));
    }
    out
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn artifact_hash(path: &Path) -> ([u8; 32], u64) {
    let data = fs::read(path).unwrap_or_else(|e| fail(format!("cannot read artifact: {e}")));
    (Sha256::digest(&data).into(), data.len() as u64)
}

fn merged_image_error(data: &[u8]) -> Option<&'static str> {
    if data.len() <= APP_OFFSET {
        return Some("artifact is too small to be a merged full-flash image");
    }
    if data[0] != 0xe9 {
        return Some("artifact is missing the ESP32-S3 bootloader image at offset 0x0");
    }
    if data[PARTITION_TABLE_OFFSET..PARTITION_TABLE_OFFSET + 2] != [0xaa, 0x50] {
        return Some("artifact is missing the ESP partition table at offset 0x8000");
    }
    if data[APP_OFFSET] != 0xe9 {
        return Some("artifact is missing the application image at offset 0x10000");
    }
    None
}

fn validate_merged_image(path: &Path) {
    let data = fs::read(path).unwrap_or_else(|e| fail(format!("cannot read artifact: {e}")));
    if let Some(message) = merged_image_error(&data) {
        fail(message);
    }
}

fn validated_signing_key(path: &Path) -> SigningKey {
    let canonical = fs::canonicalize(path)
        .unwrap_or_else(|e| fail(format!("cannot resolve private key path: {e}")));
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| fs::canonicalize(path).ok())
        .unwrap_or_else(|| fail("cannot resolve repository path"));
    if canonical.starts_with(repository) {
        fail("private key must be stored outside the repository");
    }
    #[cfg(unix)]
    {
        let mode = fs::metadata(&canonical)
            .unwrap_or_else(|e| fail(format!("cannot inspect private key permissions: {e}")))
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            fail("private key permissions must deny all group and other access (use chmod 600)");
        }
    }
    let mut private_key = read_exact::<32>(&canonical, "private key");
    let signing_key = SigningKey::from_bytes(&private_key)
        .unwrap_or_else(|e| fail(format!("invalid private key: {e}")));
    private_key.zeroize();
    let configured = decode_hex::<32>(
        include_str!("../release/release_pubkey.hex"),
        "release public key",
    );
    let derived: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    if derived != configured {
        fail("private key does not match release/release_pubkey.hex");
    }
    signing_key
}

fn expected_manifest(commit: &str, version: &str, size: u64, hash: &[u8; 32]) -> String {
    if commit.is_empty() || version.is_empty() || commit.contains('\n') || version.contains('\n') {
        fail("commit and version must be non-empty single-line values");
    }
    format!(
        "format={FORMAT}\nrepository={REPOSITORY}\nboard={BOARD}\nprofile={PROFILE}\ncommit={commit}\nversion={version}\nartifact={ARTIFACT}\nimage_layout={IMAGE_LAYOUT}\nflash_size={FLASH_SIZE}\nsize={size}\nsha256={}\nflash_offset={FLASH_OFFSET}\n",
        encode_hex(hash)
    )
}

fn parse_identity(manifest: &str) -> Result<(String, String), String> {
    let lines: Vec<&str> = manifest.lines().collect();
    if lines.len() != 12 {
        return Err("manifest must contain exactly twelve ordered fields".to_string());
    }
    let fixed = [
        ("format", FORMAT),
        ("repository", REPOSITORY),
        ("board", BOARD),
        ("profile", PROFILE),
        ("artifact", ARTIFACT),
        ("image_layout", IMAGE_LAYOUT),
        ("flash_size", FLASH_SIZE),
        ("flash_offset", FLASH_OFFSET),
    ];
    for (key, expected) in fixed {
        let line = lines
            .iter()
            .find(|line| line.starts_with(&format!("{key}=")))
            .ok_or_else(|| format!("manifest is missing {key}"))?;
        if *line != format!("{key}={expected}") {
            return Err(format!("manifest {key} is not {expected}"));
        }
    }
    let expected_keys = [
        "format",
        "repository",
        "board",
        "profile",
        "commit",
        "version",
        "artifact",
        "image_layout",
        "flash_size",
        "size",
        "sha256",
        "flash_offset",
    ];
    for (line, key) in lines.iter().zip(expected_keys) {
        if !line.starts_with(&format!("{key}=")) || line[key.len() + 1..].is_empty() {
            return Err(format!(
                "manifest field {key} is missing, empty, duplicated, or out of order"
            ));
        }
    }
    Ok((lines[4][7..].to_string(), lines[5][8..].to_string()))
}

fn create(args: &[String]) {
    if args.len() != 7 {
        fail("usage: release-manifest create <artifact> <manifest> <signature> <private-key> <commit> <version>");
    }
    let artifact = Path::new(&args[1]);
    if artifact.file_name().and_then(|name| name.to_str()) != Some(ARTIFACT) {
        fail(format!("artifact must be named {ARTIFACT}"));
    }
    validate_merged_image(artifact);
    let (hash, size) = artifact_hash(artifact);
    let manifest = expected_manifest(&args[5], &args[6], size, &hash);
    let signing_key = validated_signing_key(Path::new(&args[4]));
    let digest: [u8; 32] = Sha256::digest(manifest.as_bytes()).into();
    let signature = signing_key
        .sign_raw(&digest, &[0u8; 32])
        .unwrap_or_else(|e| fail(format!("could not sign manifest: {e}")));
    fs::write(&args[2], manifest).unwrap_or_else(|e| fail(format!("cannot write manifest: {e}")));
    fs::write(&args[3], signature.to_bytes())
        .unwrap_or_else(|e| fail(format!("cannot write signature: {e}")));
}

fn verify(args: &[String]) {
    if args.len() != 5 {
        fail("usage: release-manifest verify <artifact> <manifest> <signature> <public-key>");
    }
    let artifact = PathBuf::from(&args[1]);
    if artifact.file_name().and_then(|name| name.to_str()) != Some(ARTIFACT) {
        fail(format!("artifact must be named {ARTIFACT}"));
    }
    validate_merged_image(&artifact);
    let manifest =
        fs::read_to_string(&args[2]).unwrap_or_else(|e| fail(format!("cannot read manifest: {e}")));
    if !manifest.ends_with('\n') || manifest.contains("\r") {
        fail("manifest must use canonical LF line endings and end with one newline");
    }
    let (commit, version) = parse_identity(&manifest).unwrap_or_else(|message| fail(message));
    let (hash, size) = artifact_hash(&artifact);
    if manifest != expected_manifest(&commit, &version, size, &hash) {
        fail("manifest does not exactly match the artifact");
    }
    let public_text = fs::read_to_string(&args[4])
        .unwrap_or_else(|e| fail(format!("cannot read public key: {e}")));
    let public_key = decode_hex::<32>(&public_text, "release public key");
    let compiled_public_key = decode_hex::<32>(
        include_str!("../release/release_pubkey.hex"),
        "compiled release public key",
    );
    if public_key != compiled_public_key {
        fail("runtime public key does not match the verifier's compiled trust anchor");
    }
    if public_key.iter().all(|byte| *byte == 0) {
        fail("release public key must not be all zeros");
    }
    let signature_bytes = read_exact::<64>(Path::new(&args[3]), "manifest signature");
    let signature = Signature::try_from(signature_bytes.as_slice())
        .unwrap_or_else(|e| fail(format!("invalid signature encoding: {e}")));
    let verifier = VerifyingKey::from_bytes(&public_key)
        .unwrap_or_else(|e| fail(format!("invalid release public key: {e}")));
    let digest: [u8; 32] = Sha256::digest(manifest.as_bytes()).into();
    verifier
        .verify_raw(&digest, &signature)
        .unwrap_or_else(|_| fail("manifest signature verification failed"));
    println!(
        "Verified {ARTIFACT}: {size} bytes, sha256={}",
        encode_hex(&hash)
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("create") => create(&args),
        Some("verify") => verify(&args),
        Some("check-key") if args.len() == 2 => {
            let _ = validated_signing_key(Path::new(&args[1]));
            println!("Private key location, permissions, length, and public identity verified");
        }
        _ => fail("usage: release-manifest <create|verify> ..."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_release_public_key_is_valid_and_nonzero() {
        let key = decode_hex::<32>(
            include_str!("../release/release_pubkey.hex"),
            "release public key",
        );
        assert!(key.iter().any(|byte| *byte != 0));
        VerifyingKey::from_bytes(&key).expect("configured x-only public key must be valid");
    }

    #[test]
    fn merged_image_requires_bootloader_partition_table_and_application() {
        let mut image = vec![0xff; APP_OFFSET + 1];
        assert!(merged_image_error(&image).is_some());

        image[0] = 0xe9;
        assert!(merged_image_error(&image).is_some());

        image[PARTITION_TABLE_OFFSET..PARTITION_TABLE_OFFSET + 2].copy_from_slice(&[0xaa, 0x50]);
        assert!(merged_image_error(&image).is_some());

        image[APP_OFFSET] = 0xe9;
        assert_eq!(merged_image_error(&image), None);

        let application_only = vec![0xe9; APP_OFFSET];
        assert!(merged_image_error(&application_only).is_some());
    }

    #[test]
    fn canonical_manifest_binds_every_release_property() {
        let hash = [0xabu8; 32];
        let manifest = expected_manifest("commit-id", "4.1.0", 12345, &hash);
        assert_eq!(
            manifest,
            concat!(
                "format=kassigner-release-v1\n",
                "repository=kas-builder/KasSigner-M5Stack-fork-brt\n",
                "board=m5stack-cores3\n",
                "profile=production\n",
                "commit=commit-id\n",
                "version=4.1.0\n",
                "artifact=kassigner-m5stack.bin\n",
                "image_layout=merged-full-flash\n",
                "flash_size=16mb\n",
                "size=12345\n",
                "sha256=abababababababababababababababababababababababababababababababab\n",
                "flash_offset=0x0\n",
            )
        );
    }

    #[test]
    fn signature_rejects_a_changed_manifest_digest() {
        let private = [0u8; 31].into_iter().chain([3u8]).collect::<Vec<_>>();
        let private: [u8; 32] = private.try_into().unwrap();
        let signer = SigningKey::from_bytes(&private).unwrap();
        let original: [u8; 32] = Sha256::digest(b"original manifest").into();
        let changed: [u8; 32] = Sha256::digest(b"changed manifest").into();
        let signature = signer.sign_raw(&original, &[0u8; 32]).unwrap();
        signer
            .verifying_key()
            .verify_raw(&original, &signature)
            .unwrap();
        assert!(signer
            .verifying_key()
            .verify_raw(&changed, &signature)
            .is_err());
    }

    #[test]
    fn manifest_rejects_changed_identity_fields_and_noncanonical_structure() {
        let valid = expected_manifest("commit-id", "4.1.0", 12345, &[0xabu8; 32]);
        assert_eq!(
            parse_identity(&valid).unwrap(),
            ("commit-id".into(), "4.1.0".into())
        );

        let mutations = [
            valid.replace(
                "repository=kas-builder/KasSigner-M5Stack-fork-brt",
                "repository=attacker/fork",
            ),
            valid.replace("board=m5stack-cores3", "board=waveshare"),
            valid.replace("profile=production", "profile=development"),
            valid.replace("artifact=kassigner-m5stack.bin", "artifact=other.bin"),
            valid.replace(
                "image_layout=merged-full-flash",
                "image_layout=application-only",
            ),
            valid.replace("flash_size=16mb", "flash_size=4mb"),
            valid.replace("flash_offset=0x0", "flash_offset=0x10000"),
            valid.replacen(
                "commit=commit-id\n",
                "commit=commit-id\ncommit=duplicate\n",
                1,
            ),
            format!("unknown=value\n{valid}"),
            valid.replace(
                "commit=commit-id\nversion=4.1.0",
                "version=4.1.0\ncommit=commit-id",
            ),
        ];
        for mutation in mutations {
            assert!(
                parse_identity(&mutation).is_err(),
                "accepted mutation:\n{mutation}"
            );
        }
    }

    #[test]
    fn manifest_content_changes_when_artifact_metadata_changes() {
        let baseline = expected_manifest("commit-id", "4.1.0", 12345, &[0xabu8; 32]);
        assert_ne!(
            baseline,
            expected_manifest("commit-id", "4.1.0", 12346, &[0xabu8; 32])
        );
        assert_ne!(
            baseline,
            expected_manifest("commit-id", "4.1.0", 12345, &[0xacu8; 32])
        );
        assert_ne!(
            baseline,
            expected_manifest("other-commit", "4.1.0", 12345, &[0xabu8; 32])
        );
        assert_ne!(
            baseline,
            expected_manifest("commit-id", "4.1.1", 12345, &[0xabu8; 32])
        );
    }
}
