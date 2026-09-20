//! Tests verifying that `apps/hx-desktop` reuses the exact web UI bundle from `crates/hx-server`.
//!
//! ## Why this matters
//!
//! Requirement #2 explicitly forbids forking, copying, or duplicating the web client bundle.
//! Two bundles drift out of sync immediately. These tests assert:
//! 1. `tauri.conf.json` configures `frontendDist` pointing to `../../crates/hx-server/static`.
//! 2. That directory exists and contains `index.html`.
//! 3. The `BUNDLE_HTML` embedded by `hx-desktop` is byte-identical to `crates/hx-server/static/index.html`.
//! 4. Canonical paths of both references resolve to the exact same file on disk.

use std::fs;
use std::path::Path;

#[test]
fn tauri_conf_references_the_server_static_bundle() {
    // Read `tauri.conf.json` and verify `build.frontendDist` references `crates/hx-server/static`.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let conf_path = Path::new(manifest_dir).join("tauri.conf.json");
    let raw = fs::read_to_string(&conf_path).expect("tauri.conf.json must be readable");
    let conf: serde_json::Value =
        serde_json::from_str(&raw).expect("tauri.conf.json must be valid JSON");

    let frontend_dist = conf
        .get("build")
        .and_then(|b| b.get("frontendDist"))
        .and_then(|v| v.as_str())
        .expect("build.frontendDist must be configured as a string");

    assert_eq!(
        frontend_dist, "../../crates/hx-server/static",
        "frontendDist must point directly to crates/hx-server/static rather than a local copy"
    );

    let resolved_dir = Path::new(manifest_dir).join(frontend_dist);
    assert!(
        resolved_dir.exists(),
        "resolved static directory must exist on disk: {}",
        resolved_dir.display()
    );

    let index_file = resolved_dir.join("index.html");
    assert!(
        index_file.is_file(),
        "index.html must exist in the referenced static directory: {}",
        index_file.display()
    );
}

#[test]
fn bundle_asset_resolves_to_the_exact_same_canonical_file() {
    // The path referenced by `hx-desktop` and the path referenced by `hx-server`
    // must canonicalize to the exact same file in the filesystem.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let desktop_asset_path = Path::new(manifest_dir).join(hx_desktop::BUNDLE_RELATIVE_PATH);
    let server_asset_path =
        Path::new(manifest_dir).join("../../crates/hx-server/static/index.html");

    let canonical_desktop = fs::canonicalize(&desktop_asset_path)
        .expect("canonicalizing desktop bundle reference must succeed");
    let canonical_server = fs::canonicalize(&server_asset_path)
        .expect("canonicalizing server bundle reference must succeed");

    assert_eq!(
        canonical_desktop, canonical_server,
        "the desktop bundle asset and the server bundle asset must be the exact same file"
    );
}

#[test]
fn embedded_bundle_html_is_byte_identical_to_server_static_file() {
    // The embedded BUNDLE_HTML in `hx-desktop` must be byte-for-byte identical to
    // the static file on disk. If someone created a divergent HTML file, this fails.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let file_path = Path::new(manifest_dir).join(hx_desktop::BUNDLE_RELATIVE_PATH);
    let on_disk_content = fs::read_to_string(&file_path)
        .expect("reading crates/hx-server/static/index.html must succeed");

    assert_eq!(
        hx_desktop::BUNDLE_HTML,
        on_disk_content,
        "embedded BUNDLE_HTML must match crates/hx-server/static/index.html byte for byte"
    );

    // Verify key markers of the real hx web client are present
    assert!(
        hx_desktop::BUNDLE_HTML.contains("<title>hx</title>"),
        "bundle must contain the hx web client title"
    );
    assert!(
        hx_desktop::BUNDLE_HTML.contains("hx.api.token"),
        "bundle must contain the API token storage key"
    );
    assert!(
        hx_desktop::BUNDLE_HTML.contains("apiFetch"),
        "bundle must contain the authenticated apiFetch helper"
    );
}
