//! Process-level integration test for `cloakrs sanitize` piping, exercised against the
//! actual compiled binary so the stdin/stdout contract (`echo ... | cloakrs sanitize
//! --mapping m.json | cat`) is verified end-to-end rather than through internal functions.

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn test_cli_sanitize_reads_stdin_and_writes_masked_stdout() {
    let root =
        std::env::temp_dir().join(format!("cloakrs_cli_sanitize_pipe_{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let mapping_path = root.join("mapping.json");

    let exe = env!("CARGO_BIN_EXE_cloakrs");
    let mut child = Command::new(exe)
        .args(["--quiet", "sanitize", "--mapping"])
        .arg(&mapping_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cloakrs binary");

    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(b"email jane@example.com\n")
        .expect("failed to write to child stdin");

    let output = child.wait_with_output().expect("failed to wait on child");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("[EMAIL_1]"), "stdout was: {stdout}");
    assert!(!stdout.contains("jane@example.com"), "stdout was: {stdout}");
    assert!(mapping_path.exists());

    let mapping_contents = std::fs::read_to_string(&mapping_path).unwrap();
    assert!(mapping_contents.contains("jane@example.com"));

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn test_cli_sanitize_refuses_overwrite_without_force() {
    let root = std::env::temp_dir().join(format!(
        "cloakrs_cli_sanitize_overwrite_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let mapping_path = root.join("mapping.json");
    std::fs::write(&mapping_path, "{}").unwrap();

    let exe = env!("CARGO_BIN_EXE_cloakrs");
    let mut child = Command::new(exe)
        .args(["--quiet", "sanitize", "--mapping"])
        .arg(&mapping_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cloakrs binary");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"hello jane@example.com\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--force"), "stderr was: {stderr}");

    std::fs::remove_dir_all(&root).ok();
}

#[cfg(unix)]
#[test]
fn test_cli_sanitize_mapping_file_mode_is_0600() {
    use std::os::unix::fs::PermissionsExt;

    let root =
        std::env::temp_dir().join(format!("cloakrs_cli_sanitize_mode_{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let mapping_path = root.join("mapping.json");

    let exe = env!("CARGO_BIN_EXE_cloakrs");
    let mut child = Command::new(exe)
        .args(["--quiet", "sanitize", "--mapping"])
        .arg(&mapping_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cloakrs binary");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"hello jane@example.com\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());

    let mode = std::fs::metadata(&mapping_path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn test_cli_sanitize_help_contains_secret_warning() {
    let exe = env!("CARGO_BIN_EXE_cloakrs");
    let output = Command::new(exe)
        .args(["sanitize", "--help"])
        .output()
        .expect("failed to run cloakrs sanitize --help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("Treat it like a secret"),
        "help was: {stdout}"
    );

    let output = Command::new(exe)
        .args(["restore", "--help"])
        .output()
        .expect("failed to run cloakrs restore --help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("Treat it like a secret"),
        "help was: {stdout}"
    );
}

#[test]
fn test_cli_sanitize_then_restore_end_to_end_via_files() {
    let root = std::env::temp_dir().join(format!("cloakrs_cli_e2e_{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let input_path = root.join("input.txt");
    let mapping_path = root.join("mapping.json");
    let clean_path = root.join("clean.txt");
    std::fs::write(&input_path, "Contact jane@example.com about the invoice.").unwrap();

    let exe = env!("CARGO_BIN_EXE_cloakrs");
    let status = Command::new(exe)
        .args(["--quiet", "sanitize"])
        .arg(&input_path)
        .args(["--mapping"])
        .arg(&mapping_path)
        .args(["--output"])
        .arg(&clean_path)
        .status()
        .unwrap();
    assert!(status.success());

    // Simulate an LLM response echoing the placeholder with different casing/whitespace.
    let response_path = root.join("response.txt");
    std::fs::write(&response_path, "Reply sent regarding [ email_1 ] already.").unwrap();
    let restored_path = root.join("restored.txt");
    let status = Command::new(exe)
        .args(["--quiet", "restore"])
        .arg(&response_path)
        .args(["--mapping"])
        .arg(&mapping_path)
        .args(["--output"])
        .arg(&restored_path)
        .status()
        .unwrap();
    assert!(status.success());

    let restored = std::fs::read_to_string(&restored_path).unwrap();
    assert_eq!(restored, "Reply sent regarding jane@example.com already.");

    std::fs::remove_dir_all(&root).ok();
}

fn sanitize_file(
    input: &std::path::Path,
    mapping: &std::path::Path,
    extra: &[&str],
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_cloakrs"))
        .args(["--quiet", "sanitize"])
        .arg(input)
        .arg("--mapping")
        .arg(mapping)
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn test_nested_url_sanitization_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let mapping = dir.path().join("mapping.json");
    let original = "visit https://example.com?email=jane%40example.com and https://example.com?ssn=123-45-6789";
    std::fs::write(&input, original).unwrap();
    let output = sanitize_file(&input, &mapping, &["--locale", "us"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let clean = String::from_utf8(output.stdout).unwrap();
    assert!(!clean.contains("jane"));
    let mapping: cloakrs_core::PromptMapping =
        serde_json::from_str(&std::fs::read_to_string(mapping).unwrap()).unwrap();
    assert_eq!(mapping.restore(&clean), original);
}

#[test]
fn test_mapping_cannot_alias_input_or_output() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let mapping = dir.path().join("mapping.json");
    std::fs::write(&input, "jane@example.com").unwrap();
    assert!(!sanitize_file(&input, &input, &["--force"]).status.success());
    assert!(
        !sanitize_file(&input, &mapping, &["--output", mapping.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(std::fs::read_to_string(&input).unwrap(), "jane@example.com");
    assert!(!mapping.exists());
    std::fs::hard_link(&input, &mapping).unwrap();
    assert!(!sanitize_file(&input, &mapping, &["--force"])
        .status
        .success());
}

#[cfg(unix)]
#[test]
fn test_mapping_symlinks_are_not_followed() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let mapping = dir.path().join("mapping.json");
    let target = dir.path().join("target.json");
    std::fs::write(&input, "jane@example.com").unwrap();
    symlink(&target, &mapping).unwrap();
    assert!(!sanitize_file(&input, &mapping, &[]).status.success());
    assert!(!target.exists());
    std::fs::write(&target, "keep me").unwrap();
    assert!(sanitize_file(&input, &mapping, &["--force"])
        .status
        .success());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep me");
    assert!(!std::fs::symlink_metadata(&mapping)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[cfg(unix)]
#[test]
fn test_force_replaces_permissive_mapping_with_private_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let mapping = dir.path().join("mapping.json");
    std::fs::write(&input, "jane@example.com").unwrap();
    std::fs::write(&mapping, "{}").unwrap();
    std::fs::set_permissions(&mapping, std::fs::Permissions::from_mode(0o644)).unwrap();
    let old = std::fs::File::open(&mapping).unwrap();
    assert!(sanitize_file(&input, &mapping, &["--force"])
        .status
        .success());
    // The previous inode was never filled with the new sensitive data.
    use std::io::Read;
    let mut old_contents = String::new();
    (&old).read_to_string(&mut old_contents).unwrap();
    assert_eq!(old_contents, "{}");
    assert_eq!(
        std::fs::metadata(&mapping).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
