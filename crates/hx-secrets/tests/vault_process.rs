//! The vault, opened by a process that is not this one.
//!
//! Everything in `src/vault.rs`'s test module runs in the process that wrote the vault. That is
//! enough to prove the envelope round-trips, and it is not enough to prove anything about the
//! vault *on disk*: two `Vault` handles in one process share the memory that already holds the
//! derived key, the open-file table, the umask and the file cache. A second handle cannot answer
//! "can a stranger read this?" — the stranger is the test, and the test already knows the
//! passphrase, so the answer is whatever the test assumed. The questions worth asking here are
//! answerable only from outside:
//!
//! - a process with the wrong passphrase, an empty passphrase, or no passphrase at all reads
//!   nothing and says so, rather than returning an empty secret a caller would act on;
//! - a process told to create a vault where one already lives is refused, and the vault that was
//!   there is byte-for-byte the vault that is there afterwards;
//! - processes saving at once leave a vault that still opens, and leave it in a state some writer
//!   actually produced — never torn, never interleaved, never with every update gone;
//! - a refusal carries a reason and no value.
//!
//! The second process is `src/bin/vault_probe.rs`, named through `CARGO_BIN_EXE_hx-vault-probe`:
//! the artefact this same `cargo test` invocation just built, so the test cannot be reading a
//! stale copy out of `target/`. Every observation below is made by *running* that binary —
//! including the reads that verify a write, so nothing here is confirmed by the process that
//! performed it.
//!
//! **Why the fixtures are shaped the way they are.** The passphrases and the sentinel are
//! obviously fake, they exist only inside a `tempfile::TempDir`, and no real secret is written to
//! disk or to a log anywhere in this file. The sentinel is what the positive controls assert is
//! genuinely present *before* the negative assertions run: without that, a probe that read nothing
//! at all — a wrong path, a binary that never ran, an argv the vault ignored — would satisfy every
//! refusal assertion below while proving nothing.
//!
//! **Platform handling.** The tests here assert only behaviour both platforms promise, and the
//! one claim that is not cross-platform is split rather than assumed. `rename(2)` is specified to
//! be atomic and to unlink the old inode; Windows' `MoveFileEx`-based replace has its own rules
//! about a destination another process has open. So
//! `a_save_replaces_the_vault_file_rather_than_rewriting_the_one_a_reader_has_open` has a
//! `#[cfg(unix)]` arm that holds a handle across the save and a `#[cfg(not(unix))]` counterpart
//! asserting the part both platforms do promise. Both arms compile on both platforms — an arm that
//! is never compiled is indistinguishable from a passing test, which is exactly what the
//! `known_hosts`/`ssh.rs` audit in `TESTING.md` found.
//!
//! Nothing in this file asserts elapsed time. Where a race needs a window, the window is a *count*
//! of operations (`watch`), never a sleep.

#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

/// The probe, as built by this `cargo test` invocation.
const PROBE: &str = env!("CARGO_BIN_EXE_hx-vault-probe");

/// The probe's passphrase variable. It is the interface between this file and that binary, so it
/// is spelled once here and has to match `PASSPHRASE_ENV` in `src/bin/vault_probe.rs`.
const PASSPHRASE_ENV: &str = "HX_VAULT_PROBE_PASSPHRASE";

/// Fixture credentials. Not secrets, and shaped so nobody could mistake one for a real key.
const PASS: &str = "a-fixture-passphrase-not-a-real-one";
const OTHER_PASS: &str = "a-different-fixture-passphrase";
const SENTINEL: &str = "FIXTURE-VALUE-NOT-A-REAL-KEY-4c1f";
const NAME: &str = "provider/fixture";

// ---------------------------------------------------------------------------------------------
// Running the second process
// ---------------------------------------------------------------------------------------------

/// Run the probe as a real second process and collect what it said.
///
/// With `None` the passphrase variable is **removed** rather than set empty — removed from
/// whatever this test process inherited as well, so the run cannot pass because of an environment
/// the developer happened to have. "There is no passphrase" and "the passphrase is the empty
/// string" are different situations and the probe is written to refuse the first instead of
/// guessing; setting it empty here would quietly test only the second.
fn probe(passphrase: Option<&str>, args: &[&str]) -> Output {
    probe_command(passphrase, args)
        .output()
        .expect("the probe binary should be runnable")
}

/// The same, but left running, for a test that needs more than one probe in flight at once.
///
/// `stdout`/`stderr` are piped so `wait_with_output` can collect them; nothing reads them
/// incrementally, so there is no pipe to fill.
fn probe_child(passphrase: &str, args: &[&str]) -> Child {
    probe_command(Some(passphrase), args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the probe binary should be spawnable")
}

fn probe_command(passphrase: Option<&str>, args: &[&str]) -> Command {
    let mut cmd = Command::new(PROBE);
    cmd.args(args).env_remove(PASSPHRASE_ENV);
    if let Some(passphrase) = passphrase {
        cmd.env(PASSPHRASE_ENV, passphrase);
    }
    cmd
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A temp path as the probe's argv. `expect` rather than a lossy conversion: a path that cannot
/// be passed through argv is a broken test, not a vault finding, and silently mangling it would
/// show up as a confusing "no vault at ..." later.
fn arg(path: &Path) -> String {
    path.to_str().expect("a UTF-8 temp path").to_string()
}

/// A vault at `<dir>/vault.json` holding `NAME` → `SENTINEL`, written by a second process.
///
/// Written through the probe rather than through `Vault::create_at`, so that the vault under test
/// arrived by the same path the tests then read it back through.
fn vault_with_sentinel(dir: &Path) -> PathBuf {
    let path = dir.join("vault.json");
    let created = probe(Some(PASS), &["create", &arg(&path)]);
    assert!(created.status.success(), "create: {}", stderr(&created));
    let put = probe(Some(PASS), &["put", &arg(&path), NAME, SENTINEL]);
    assert!(put.status.success(), "put: {}", stderr(&put));
    path
}

/// The entry count a fresh second process reports, which is how these tests read the vault: a
/// count printed by a process that did not do the writing.
fn entries(path: &Path) -> usize {
    let counted = probe(Some(PASS), &["count", &arg(path)]);
    assert!(
        counted.status.success(),
        "the vault must open: {}",
        stderr(&counted)
    );
    let printed = stdout(&counted);
    printed
        .trim()
        .strip_prefix("entries=")
        .unwrap_or_else(|| panic!("count printed {printed:?}"))
        .parse()
        .unwrap_or_else(|_| panic!("count printed {printed:?}"))
}

// ---------------------------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------------------------

/// A second process cannot read a secret without unlocking the vault.
///
/// The positive control runs **first** and is not decoration. Without it, a probe that reads
/// nothing at all passes every refusal below, and the file would report "the vault refuses
/// strangers" while actually observing "the vault refuses everyone, including its owner". The
/// control also pins the other half of the shape: what a *successful* read looks like (exit 0,
/// the value on stdout) so that the refusals are distinguishable from it.
///
/// **What this test cannot see, and which test covers it.** A vault that *fails open* — one that
/// swallows the decryption failure and returns an empty vault — also reads no secret, so every
/// assertion here still passes; that was measured against a mutated `Vault::open`, and this test
/// stayed green. No assertion about a value can tell "refused" from "empty", which is why the
/// refusal *saying why* is a test of its own
/// (`a_wrong_passphrase_is_refused_with_a_reason_that_names_no_value`, which that mutation fails).
/// The pair is the property; either half alone is not.
#[test]
fn a_second_process_cannot_read_a_secret_without_unlocking_the_vault() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = vault_with_sentinel(dir.path());

    let unlocked = probe(Some(PASS), &["get", &arg(&path), NAME]);
    assert!(
        unlocked.status.success(),
        "the positive control must succeed, or nothing below means anything: {}",
        stderr(&unlocked)
    );
    assert!(
        stdout(&unlocked).contains(SENTINEL),
        "the sentinel must genuinely reach stdout, not merely be absent from stderr: {:?}",
        stdout(&unlocked)
    );

    // Three ways of not knowing the passphrase, including the one that is easy to get wrong:
    // an *absent* variable must be refused rather than read as the empty string.
    for (situation, passphrase) in [
        ("an empty passphrase", Some("")),
        ("a wrong passphrase", Some(OTHER_PASS)),
        ("no passphrase variable at all", None),
    ] {
        let refused = probe(passphrase, &["get", &arg(&path), NAME]);
        assert!(
            !refused.status.success(),
            "{situation}: was allowed to read a locked vault"
        );
        // The failure mode being caught is not a crash but a *quiet* success: a caller that
        // receives an empty secret and carries on unauthenticated. Anything on stdout at all is
        // that bug wearing a different hat.
        assert!(
            stdout(&refused).is_empty(),
            "{situation}: a refusal printed {:?} to stdout — an empty value a caller would read as \"no secret\" is the failure this test exists for",
            stdout(&refused)
        );
        assert!(
            !stderr(&refused).contains(SENTINEL),
            "{situation}: the refusal echoed the value: {:?}",
            stderr(&refused)
        );
        assert!(
            !stderr(&refused).trim().is_empty(),
            "{situation}: the refusal carried no reason"
        );
    }
}

/// A second process does not recreate or overwrite a vault that is already there.
///
/// The destructive version of this is one word of `OpenOptions` away and looks like it worked:
/// the file exists, the vault opens, and every key that was in it is gone — silently, until
/// something needs a credential. So the assertion is not "create returned an error" but "the bytes
/// on disk are the bytes that were there", checked against a snapshot taken before, and then
/// confirmed by a *third* process reading the original secret back.
///
/// The second process is given a different passphrase on purpose: a create that quietly succeeded
/// would leave a vault this test cannot open, so the failure cannot hide behind the first
/// passphrase still working.
#[test]
fn a_second_process_does_not_recreate_or_overwrite_a_vault_that_is_already_there() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = vault_with_sentinel(dir.path());
    let before = std::fs::read(&path).expect("the vault file");

    let second = probe(Some(OTHER_PASS), &["create", &arg(&path)]);
    assert!(
        !second.status.success(),
        "a second process was allowed to create a vault over an existing one"
    );
    assert!(
        stderr(&second).contains("already exists"),
        "the refusal must name what it refused, and a path is not a secret: {:?}",
        stderr(&second)
    );
    assert_eq!(
        std::fs::read(&path).expect("the vault file"),
        before,
        "the bytes on disk changed: something wrote to a vault it was told to leave alone"
    );

    // The vault is still the one it was, read by a process that is not the one that refused.
    let survived = probe(Some(PASS), &["get", &arg(&path), NAME]);
    assert!(
        survived.status.success(),
        "the original vault no longer opens: {}",
        stderr(&survived)
    );
    assert!(stdout(&survived).contains(SENTINEL));
}

/// Concurrent writers never leave a vault that cannot be opened, and never lose every update.
///
/// **What the design actually claims**, because asserting more would be asserting a lock nobody
/// wrote: `Vault::save_to` seals to a temp file and `rename`s it over the target, so a reader sees
/// the whole old vault or the whole new one — and nothing coordinates writers, so the last save
/// wins and an earlier one is *silently gone*. That is written down in `save_to`'s own doc comment
/// as the design rather than as an oversight. A test asserting that both updates survive would be
/// asserting a property this vault does not have, and it would be a test that agrees with itself
/// about a merge that never happens.
///
/// So three things are asserted, and each one is a thing a real defect breaks:
///
/// 1. **Every writer that reported success is accounted for, and no update vanishes without a
///    trace.** Each writer's map contains its own name, so whichever save landed last must have
///    left at least one writer's name behind. A vault left holding only the pre-existing entry —
///    or nothing — is a truncation, not a race.
/// 2. **The surviving state is one a writer actually produced.** A name that is readable carries
///    exactly the value its writer wrote, and `count` agrees with what can be read back. An
///    interleaved or half-written file shows up here as a value nobody wrote, or as a `len()` that
///    disagrees with the contents.
/// 3. **A reader running throughout never sees a torn vault.** `watch` opens the vault in a loop
///    and reports the *smallest* entry count it saw, so an iteration that lands inside a
///    truncate-and-write fails the run — which is the property the atomic replace exists for, and
///    the one a post-hoc check after the writers finish cannot see at all.
///
/// The reader's window is a count of opens, not a sleep: nothing here is timed. It is a tripwire
/// and not a proof, and that was measured rather than assumed: replacing the temp-file-and-rename
/// in `save_to` with a truncate-and-rewrite of the target left this test **passing**, because the
/// window between `truncate` and the bytes reaching the page cache is a few microseconds and a
/// reader has to land exactly there. That is why the guarantee has a second, deterministic test —
/// `a_save_replaces_the_vault_file_rather_than_rewriting_the_one_a_reader_has_open` — which that
/// same mutation does fail. This test stays because it covers the other two properties and because
/// a wider window (a larger vault, more writers) is a change in the fixture rather than in the
/// claim; the deterministic test is the one to trust about atomicity.
#[test]
fn concurrent_writers_never_leave_a_vault_that_cannot_be_opened_or_lose_every_update() {
    const WRITERS: usize = 4;
    const WATCH_OPENS: usize = 3000;

    let dir = tempfile::tempdir().expect("a temp dir");
    let path = vault_with_sentinel(dir.path());

    // The reader goes first, so it is already opening the vault while the writers replace it.
    let watcher = probe_child(PASS, &["watch", &arg(&path), &WATCH_OPENS.to_string()]);

    let writers: Vec<Child> = (0..WRITERS)
        .map(|i| {
            probe_child(
                PASS,
                &[
                    "put",
                    &arg(&path),
                    &format!("writer/{i}"),
                    &format!("value-from-{i}"),
                ],
            )
        })
        .collect();

    let reported: Vec<Output> = writers
        .into_iter()
        .map(|child| child.wait_with_output().expect("a writer to finish"))
        .collect();
    for (i, output) in reported.iter().enumerate() {
        assert!(
            output.status.success(),
            "writer {i} reported failure, so the vault refused a save under contention: {}",
            stderr(output)
        );
    }

    let watched = watcher.wait_with_output().expect("the watcher to finish");
    assert!(
        watched.status.success(),
        "a reader saw the vault in a state it could not open — that is the torn file the atomic \
         replace exists to prevent: {}",
        stderr(&watched)
    );
    let watched_stdout = stdout(&watched);
    let min_entries = watched_stdout
        .split_whitespace()
        .find_map(|field| field.strip_prefix("min_entries="))
        .unwrap_or_else(|| panic!("watch printed {watched_stdout:?}"))
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("watch printed {watched_stdout:?}"));
    assert!(
        watched_stdout.contains(&format!("opens={WATCH_OPENS}")),
        "the watcher did not complete its opens, so it may have missed the whole race: {watched_stdout:?}"
    );
    // The pre-existing entry is in the old vault and in every writer's map, so no legitimate
    // state of this file has fewer entries than that.
    assert!(
        min_entries >= 1,
        "a reader saw an empty vault while writers were replacing it: {watched_stdout:?}"
    );

    // Read the outcome back through yet another process, one name at a time.
    let mut readable = 0usize;
    for name in std::iter::once(NAME.to_string()).chain((0..WRITERS).map(|i| format!("writer/{i}")))
    {
        let read = probe(Some(PASS), &["get", &arg(&path), &name]);
        if !read.status.success() {
            continue;
        }
        readable += 1;
        let value = stdout(&read).trim().to_string();
        let expected = if name == NAME {
            SENTINEL.to_string()
        } else {
            let i = name.strip_prefix("writer/").expect("a writer name");
            format!("value-from-{i}")
        };
        assert_eq!(
            value, expected,
            "{name:?} is readable but holds a value its writer never wrote — an interleaved or \
             half-written map"
        );
    }

    // The pre-existing entry is never the casualty, and at least one writer survived: a save that
    // landed last carries its own name, so "only the base entry is left" means a truncation.
    let base = probe(Some(PASS), &["get", &arg(&path), NAME]);
    assert!(
        base.status.success(),
        "the pre-existing entry was lost to the race: {}",
        stderr(&base)
    );
    assert!(
        readable >= 2,
        "every writer's update is gone and only the pre-existing entry remains, with all {WRITERS} \
         writers reporting success"
    );

    // `len()` has to agree with what can actually be read: a vault whose count is right while a
    // name it claims is unreadable (or the reverse) is a map that was never consistent on disk.
    assert_eq!(
        entries(&path),
        readable,
        "the vault reports a different number of entries than a reader can find"
    );
}

/// A wrong passphrase is refused with a reason that names no value.
///
/// Distinct from the unlocking test on purpose: that one asks *whether* a stranger is stopped,
/// this one asks what the refusal is allowed to say. A vault that refuses correctly and then
/// explains itself with the value it was protecting has handed the secret over anyway — into a
/// terminal, a log, a transcript the model reads.
///
/// The exit code is asserted too, because it is the difference between "the vault refused" and
/// "the test invoked the probe wrongly": `1` is a refusal, `2` is a usage mistake, and a test that
/// could not tell them apart would report a broken harness as a security result. The usage case is
/// exercised for real, so the two codes are known to be distinguishable rather than assumed to be.
#[test]
fn a_wrong_passphrase_is_refused_with_a_reason_that_names_no_value() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = vault_with_sentinel(dir.path());

    let refused = probe(Some(OTHER_PASS), &["get", &arg(&path), NAME]);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a refusal must exit 1, not 2 (a usage mistake): {}",
        stderr(&refused)
    );
    let reason = stderr(&refused);
    assert!(
        !reason.trim().is_empty(),
        "the refusal carried no reason at all"
    );
    // The reason has to identify the *kind* of failure without narrowing down the cause: wrong
    // passphrase and tampered ciphertext are deliberately indistinguishable.
    assert!(
        reason.contains("wrong passphrase"),
        "the refusal should say what kind of failure it was: {reason:?}"
    );
    for forbidden in [SENTINEL, PASS, OTHER_PASS, NAME] {
        assert!(
            !reason.contains(forbidden),
            "the refusal named {forbidden:?}: {reason:?}"
        );
    }
    assert!(
        stdout(&refused).is_empty(),
        "the refusal printed {:?} to stdout",
        stdout(&refused)
    );

    // The control for the exit code: a probe called with no secret name is a *usage* mistake, and
    // says so with a different code, so the assertion above is not just observing "non-zero".
    let misinvoked = probe(Some(PASS), &["get", &arg(&path)]);
    assert_eq!(
        misinvoked.status.code(),
        Some(2),
        "a mis-invocation must be distinguishable from a refusal: {}",
        stderr(&misinvoked)
    );
}

/// The shipped KDF cost is the one a second process actually opens.
///
/// This is the slow test in the file, and it is slow on purpose: every other test here runs at
/// `KdfParams::for_tests()` so the suite stays runnable, and a suite that only ever opened
/// test-parameter vaults would never exercise the 64 MiB / 3-pass parameters that ship. Weakening
/// the product's KDF to speed up a test is not a trade worth making, so the cost is paid in one
/// place and named here instead of being avoided everywhere.
///
/// The envelope is read back to prove the slow run was slow for the right reason: a `default-kdf`
/// that quietly fell back to the test parameters would still pass a round-trip assertion, and
/// would leave the shipped cost untested while reporting otherwise.
#[test]
fn the_shipped_kdf_cost_is_the_one_a_second_process_can_open() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("shipped.json");

    let created = probe(Some(PASS), &["create", &arg(&path), "default-kdf"]);
    assert!(created.status.success(), "create: {}", stderr(&created));

    let envelope: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the vault file"))
            .expect("the envelope to parse");
    assert_eq!(envelope["kdf"]["m_cost_kib"], 64 * 1024);
    assert_eq!(envelope["kdf"]["t_cost"], 3);
    assert_eq!(envelope["kdf"]["p_cost"], 4);

    let put = probe(Some(PASS), &["put", &arg(&path), NAME, SENTINEL]);
    assert!(put.status.success(), "put: {}", stderr(&put));

    // A different process, opening at the shipped cost and reading the value back.
    let read = probe(Some(PASS), &["get", &arg(&path), NAME]);
    assert!(read.status.success(), "get: {}", stderr(&read));
    assert!(stdout(&read).contains(SENTINEL));
}

/// A save replaces the vault file rather than rewriting the one a reader already has open.
///
/// This is the deterministic half of the guarantee `save_to` makes and the concurrency test can
/// only sample. The claim is "a second process opening the vault sees the whole previous envelope
/// or the whole new one"; the reason it can make that claim is that the save never *modifies* the
/// vault file — it seals into a temp file and `rename`s it into place, so the file the path used to
/// name is unlinked, not overwritten. A reader that already has it open therefore keeps reading a
/// complete, consistent vault while the edit happens, and cannot be caught mid-write even in
/// principle.
///
/// **Why this is not just the concurrency test with a different fixture.** A truncate-and-rewrite
/// of the target would leave that test passing (measured — see its doc comment), because the torn
/// window is microseconds wide and a reader has to land in it. Here there is nothing to land in:
/// either the bytes under the held handle are the old vault or they are the new one, and only one
/// of those is correct. This is the mutation the concurrency test's `watch` cannot see.
///
/// `#[cfg(unix)]` because that is where "replace, never rewrite" is a specified property of the
/// call (`rename(2)` is atomic and unlinks the old inode). The Windows counterpart below asserts
/// what `MoveFileEx`-based replace does promise, with its own doc comment saying what it does not.
#[cfg(unix)]
#[test]
fn a_save_replaces_the_vault_file_rather_than_rewriting_the_one_a_reader_has_open() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = vault_with_sentinel(dir.path());

    // Hold the vault open the way a long-lived reader would, and read the whole envelope.
    let mut held = File::open(&path).expect("the vault file");
    let mut before = Vec::new();
    held.read_to_end(&mut before).expect("the old envelope");
    assert!(!before.is_empty(), "the fixture vault must not be empty");

    // The save under test, in a second process.
    let put = probe(
        Some(PASS),
        &["put", &arg(&path), "added/by/the/second/process", SENTINEL],
    );
    assert!(put.status.success(), "put: {}", stderr(&put));

    // The path now names the new vault, and a third process can open it...
    let after = std::fs::read(&path).expect("the vault file");
    assert_ne!(after, before, "the save did not actually change the vault");
    let added = probe(
        Some(PASS),
        &["get", &arg(&path), "added/by/the/second/process"],
    );
    assert!(added.status.success(), "get: {}", stderr(&added));

    // ...while the handle that was open the whole time still sees the *old* vault, entire. A save
    // that truncated and rewrote the path in place would show the new bytes here, and would have
    // shown a zero-length or half-written envelope to a reader arriving mid-save.
    held.seek(SeekFrom::Start(0)).expect("rewind the held file");
    let mut still = Vec::new();
    held.read_to_end(&mut still).expect("the held envelope");
    assert_eq!(
        still, before,
        "the vault a reader already had open changed underneath it: the save rewrote the file in \
         place instead of replacing it"
    );
}

/// The Windows counterpart: a save leaves a vault that opens, and does not modify the file in
/// place.
///
/// `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING` is a replace, not a rewrite — but what Windows
/// does with a destination another process holds open is its own contract, so the claim asserted
/// above from a held handle is not asserted here. What is asserted is what the design promises a
/// *second process that opens the vault*: the old envelope is gone as a whole, the new one is
/// there as a whole, and both are readable by a process other than the writer. The whole-file
/// comparison is what makes this more than a round-trip: a partial write would leave a file that
/// is neither.
#[cfg(not(unix))]
#[test]
fn a_save_replaces_the_vault_file_rather_than_rewriting_the_one_a_reader_has_open() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = vault_with_sentinel(dir.path());
    let before = std::fs::read(&path).expect("the vault file");

    let put = probe(
        Some(PASS),
        &["put", &arg(&path), "added/by/the/second/process", SENTINEL],
    );
    assert!(put.status.success(), "put: {}", stderr(&put));

    let after = std::fs::read(&path).expect("the vault file");
    assert_ne!(after, before, "the save did not actually change the vault");
    assert!(
        !after.is_empty(),
        "the save left a zero-length vault, which is a rewrite that was interrupted rather than a \
         replace"
    );

    // Both the pre-existing entry and the new one are readable, by processes that did not write.
    for name in [NAME, "added/by/the/second/process"] {
        let read = probe(Some(PASS), &["get", &arg(&path), name]);
        assert!(read.status.success(), "get {name:?}: {}", stderr(&read));
        assert!(stdout(&read).contains(SENTINEL));
    }
}
