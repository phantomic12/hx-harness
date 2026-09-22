//! The task loader, against fixture directories on disk.

use hx_core::config::SandboxProfile;
use hx_eval::task::{load_task, to_sandbox_spec};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn a_minimal_task_loads() {
    let task = load_task(fixture("minimal")).unwrap();
    assert_eq!(task.config.task.name, "test/minimal");
    assert!(task.instruction.contains("echo hello"));
    assert!(task.environment.is_none());
    assert!(task.tests.is_empty());
}

#[test]
fn a_task_with_an_environment_loads() {
    let task = load_task(fixture("with-env")).unwrap();
    let env = task.environment.expect("environment/ should be found");
    assert!(env.dockerfile.is_some());
    assert_eq!(task.config.environment.cpus, Some(2.0));
    assert_eq!(task.config.environment.memory_mb, Some(2048));
}

#[test]
fn a_task_with_a_prebuilt_image_loads() {
    let task = load_task(fixture("prebuilt")).unwrap();
    assert_eq!(
        task.config.environment.docker_image.as_deref(),
        Some("ubuntu:24.04")
    );
}

#[test]
fn a_missing_task_toml_is_not_a_task() {
    let err = load_task(fixture("not-a-task")).unwrap_err();
    assert!(err.to_string().contains("task.toml"), "{err}");
}

#[test]
fn a_missing_instruction_is_not_a_task() {
    let err = load_task(fixture("no-instruction")).unwrap_err();
    assert!(err.to_string().contains("instruction.md"), "{err}");
}

#[test]
fn a_windows_task_is_refused() {
    let err = load_task(fixture("windows")).unwrap_err();
    assert!(err.to_string().contains("Windows"), "{err}");
}

#[test]
fn the_task_maps_to_a_sandbox_spec() {
    let task = load_task(fixture("with-env")).unwrap();
    let profile = SandboxProfile::default();
    let spec = to_sandbox_spec(&task, &profile).unwrap();

    assert_eq!(spec.cpus, 2.0);
    assert_eq!(spec.memory_mb, 2048);
    assert!(!spec.network, "no-network maps to network: false");
}

#[test]
fn a_task_that_asks_for_too_much_is_refused() {
    let task = load_task(fixture("too-big")).unwrap();
    let profile = SandboxProfile::default();
    let err = to_sandbox_spec(&task, &profile).unwrap_err();
    assert!(err.to_string().contains("cpus"), "{err}");
}

#[test]
fn a_prebuilt_image_overrides_the_profile() {
    let task = load_task(fixture("prebuilt")).unwrap();
    let profile = SandboxProfile::default();
    let spec = to_sandbox_spec(&task, &profile).unwrap();
    assert_eq!(spec.image, "ubuntu:24.04");
}
