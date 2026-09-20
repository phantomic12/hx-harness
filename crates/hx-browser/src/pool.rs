//! The pool: sessions, their profiles, and the ladder they climb.
//!
//! ## What the pool adds over the ladder
//!
//! Two things, and both are about *identity* rather than convenience:
//!
//! 1. **A session's profile outlives a fetch.** [`BrowserPool::session`] mints a profile on first use
//!    and hands back the *same* one afterwards, so a login or a cleared challenge earned during one
//!    fetch is still there for the session's next one. A pool that made a fresh profile per fetch
//!    would be safe and useless: every fetch would arrive as a stranger, and the interactive rung's
//!    whole purpose — a person unblocking a session — would evaporate between calls.
//! 2. **Admission happens once, before anything is created or launched.** A refused target is turned
//!    into a report with *no attempts and no profile directory*, because a refused target must not
//!    leave state behind and must not be launched at. The tests assert the emptiness rather than the
//!    wording, since the emptiness is the security property.
//!
//! ## Concurrency
//!
//! The session map is a `std::sync::Mutex`, and the lock is held across one `create_dir_all`. That is
//! deliberate, and the alternative is worse: creating the directory *outside* the lock would let two
//! concurrent callers for one session mint two handles to the same path, which is precisely the
//! identity the map exists to provide. The critical section is a single directory creation on a local
//! filesystem, it holds no `await`, and the guard is dropped before any `.await` — so it cannot block
//! the runtime and cannot deadlock.
//!
//! A poisoned lock is recovered rather than propagated: the map holds paths and nothing else, so a
//! panic elsewhere cannot leave it inconsistent, and refusing every later fetch because an unrelated
//! task panicked would turn one failure into an outage.
//!
//! ## What is deliberately NOT done
//!
//! - **No eviction, no cap.** How long a session's profile should live is a question about sessions,
//!   which whoever owns the session store already answers. A pool that reaped on its own schedule
//!   would delete a profile a browser is still writing to, and would log a session out mid-task.
//! - **No process limit.** The stealth and interactive rungs each own a browser process, and bounding
//!   *those* is a resource policy that belongs where the processes are launched, not here. The pool's
//!   job is that two of them can never be looking at the same profile.
//! - **No retry.** A refused rung is escalated by the ladder; a transport failure is reported. A pool
//!   that retried would be the machine for burning the dear rungs that [`crate::error`] describes.

use crate::ladder::{FetchReport, Ladder};
use crate::profile::{PoolRoot, ProfileError, SessionProfile};
use crate::target::{Admission, TargetUrl};
use hx_core::ids::SessionId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A pool of isolated browser sessions, each with its own profile, all climbing one ladder.
pub struct BrowserPool {
    root: PoolRoot,
    ladder: Ladder,
    admission: Admission,
    sessions: Mutex<HashMap<SessionId, Arc<SessionProfile>>>,
}

impl BrowserPool {
    /// Build a pool. Targets are admitted under the default policy — the public internet only.
    pub fn new(root: PoolRoot, ladder: Ladder) -> Self {
        Self {
            root,
            ladder,
            admission: Admission::default(),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Admit loopback and private targets as well.
    ///
    /// A named decision rather than a widened default: the fetcher makes its requests from inside
    /// this process, so "local" is not a smaller request, it is a different capability. Two callers —
    /// the hermetic suite, whose stub server is on `127.0.0.1`, and an operator who has deliberately
    /// pointed hx at a service on their own machine. See [`Admission`].
    pub fn with_admission(mut self, admission: Admission) -> Self {
        self.admission = admission;
        self
    }

    /// The profile for a session, created on first use and reused after.
    ///
    /// The same session id always yields the same handle, which is what lets a login or a cleared
    /// challenge persist across fetches. Distinct ids always yield distinct directories — asserted in
    /// [`crate::profile`], and the reason this is safe to run in parallel.
    pub fn session(&self, id: &SessionId) -> Result<Arc<SessionProfile>, ProfileError> {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(existing) = sessions.get(id) {
            return Ok(Arc::clone(existing));
        }

        let profile = Arc::new(self.root.session(id)?);
        sessions.insert(id.clone(), Arc::clone(&profile));
        Ok(profile)
    }

    /// How many sessions this pool is holding a profile for.
    pub fn session_count(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Fetch `url` for `session`, climbing the ladder inside that session's own profile.
    ///
    /// Admission runs first. A target it refuses produces a report with no attempts and no profile
    /// directory — nothing was created, nothing was launched, and the caller still learns what was
    /// refused and why.
    pub async fn fetch(&self, session: &SessionId, url: &str) -> FetchReport {
        let target = match TargetUrl::parse_with(self.admission, url) {
            Ok(target) => target,
            Err(refusal) => return FetchReport::refused(&refusal.display, &refusal),
        };

        let profile = match self.session(session) {
            Ok(profile) => profile,
            Err(err) => return FetchReport::stopped(&target.redacted(), err.to_string()),
        };

        self.ladder.fetch(target, profile).await
    }

    pub fn ladder(&self) -> &Ladder {
        &self.ladder
    }

    pub fn root(&self) -> &PoolRoot {
        &self.root
    }

    /// The admission policy in force.
    pub fn admission(&self) -> Admission {
        self.admission
    }
}

impl std::fmt::Debug for BrowserPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The rungs are not `Debug` and their internals are not diagnostics; the shape is.
        f.debug_struct("BrowserPool")
            .field("root", &self.root.path())
            .field("rungs", &self.ladder.rungs())
            .field("admission", &self.admission)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FetchError;
    use crate::rung::{FetchRequest, Fetcher, RungKind, UntrustedPage};
    use async_trait::async_trait;
    use std::path::PathBuf;

    /// A rung that always succeeds and records the profile it was handed.
    ///
    /// The ladder's own decisions are tested in `ladder.rs` with a scripted double; what is under
    /// test here is the pool's wiring, so this rung does one thing and does it visibly.
    struct ProfileRecordingRung {
        seen: Mutex<Vec<PathBuf>>,
    }

    impl ProfileRecordingRung {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                seen: Mutex::new(Vec::new()),
            })
        }

        fn seen(&self) -> Vec<PathBuf> {
            self.seen.lock().expect("the seen lock").clone()
        }
    }

    #[async_trait]
    impl Fetcher for ProfileRecordingRung {
        fn kind(&self) -> RungKind {
            RungKind::Http
        }

        fn name(&self) -> &str {
            "profile-recorder"
        }

        async fn fetch(&self, request: &FetchRequest) -> Result<UntrustedPage, FetchError> {
            self.seen
                .lock()
                .expect("the seen lock")
                .push(request.profile.dir().to_path_buf());
            Ok(UntrustedPage::new(
                request.target.clone(),
                200,
                "text/html",
                RungKind::Http,
                "<h1>ok</h1>",
            ))
        }
    }

    /// A rung that panics if it is called at all.
    ///
    /// Used for the refused-target tests: "no rung ran" has to be a loud claim, and a rung that
    /// returned a page anyway would let the test pass while the pool launched a browser at a
    /// `file://` URL.
    struct NeverRung;

    #[async_trait]
    impl Fetcher for NeverRung {
        fn kind(&self) -> RungKind {
            RungKind::Http
        }

        fn name(&self) -> &str {
            "never"
        }

        async fn fetch(&self, request: &FetchRequest) -> Result<UntrustedPage, FetchError> {
            panic!(
                "no rung may run for a target the pool refused, but one was called with {}",
                request.target.redacted()
            )
        }
    }

    fn root() -> (tempfile::TempDir, PoolRoot) {
        let temp = tempfile::tempdir().expect("a temp directory");
        let root = PoolRoot::new(temp.path().join("pool")).expect("a pool root");
        (temp, root)
    }

    fn id(raw: &str) -> SessionId {
        SessionId::from_raw(raw)
    }

    /// A pool whose stub target is on loopback, which needs the named admission policy.
    fn pool_with(rung: Arc<dyn Fetcher>) -> (tempfile::TempDir, BrowserPool) {
        let (temp, root) = root();
        let ladder = Ladder::new(vec![rung]);
        let pool = BrowserPool::new(root, ladder).with_admission(Admission::AllowLocal);
        (temp, pool)
    }

    /// A pool under the **default** policy — the public internet only.
    ///
    /// Deliberately not `pool_with`: that one lifts the address rule for the hermetic stub, and
    /// `AllowLocal` admits the metadata address as well as loopback (asserted in
    /// [`crate::target`]'s own tests). So the refusals below are refusals *under the default
    /// policy*, and a test that used the permissive pool would be asserting nothing: the first
    /// version of this test did exactly that, and the gate caught it — the rung ran, and its
    /// "no rung may run" panic is what failed.
    fn strict_pool(rung: Arc<dyn Fetcher>) -> (tempfile::TempDir, BrowserPool) {
        let (temp, root) = root();
        (temp, BrowserPool::new(root, Ladder::new(vec![rung])))
    }

    // ---------------------------------------------------------------------------------
    // Identity: a session keeps its profile
    // ---------------------------------------------------------------------------------

    #[test]
    fn the_same_session_gets_the_same_profile_back() {
        // What makes a cleared challenge or a login worth keeping: the next fetch for this session
        // must land in the same profile, not a fresh one. `Arc::ptr_eq` rather than a path
        // comparison, because the handle is what the rungs are handed.
        let (_temp, root) = root();
        let pool = BrowserPool::new(root, Ladder::new(vec![]));

        let first = pool.session(&id("ses_same")).expect("a profile");
        let second = pool.session(&id("ses_same")).expect("a profile");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.dir(), second.dir());
        assert_eq!(pool.session_count(), 1);
    }

    #[test]
    fn a_session_that_escapes_the_root_is_refused_and_creates_nothing() {
        let (_temp, root) = root();
        let pool = BrowserPool::new(root, Ladder::new(vec![]));

        let err = pool.session(&id("../escape")).expect_err("refused");
        assert!(
            matches!(err, ProfileError::UnsafeSessionId { .. }),
            "{err:?}"
        );
        assert_eq!(
            pool.session_count(),
            0,
            "a refused id must not be remembered as a session"
        );
    }

    #[test]
    fn concurrent_calls_for_one_session_all_get_the_same_handle() {
        // The map exists for identity; a race that minted two handles for one id would be a race that
        // handed two browsers the same directory as two different profiles.
        let (_temp, root) = root();
        let pool = BrowserPool::new(root, Ladder::new(vec![]));
        let session = id("ses_race");

        let handles: Vec<Arc<SessionProfile>> = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| pool.session(&session).expect("a profile")))
                .collect();
            threads
                .into_iter()
                .map(|t| t.join().expect("no panic"))
                .collect()
        });

        assert_eq!(handles.len(), 8);
        assert!(
            handles.iter().all(|h| Arc::ptr_eq(h, &handles[0])),
            "every caller must get the same handle"
        );
        assert_eq!(pool.session_count(), 1);
    }

    #[test]
    fn distinct_sessions_get_distinct_directories() {
        let (_temp, root) = root();
        let pool = BrowserPool::new(root, Ladder::new(vec![]));

        let mut dirs: Vec<PathBuf> = (0..8)
            .map(|n| {
                pool.session(&id(&format!("ses_{n}")))
                    .expect("a profile")
                    .dir()
                    .to_path_buf()
            })
            .collect();
        let count = dirs.len();
        dirs.sort();
        dirs.dedup();

        assert_eq!(dirs.len(), count);
        assert_eq!(pool.session_count(), 8);
    }

    // ---------------------------------------------------------------------------------
    // Admission happens before anything is created or launched
    // ---------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_refused_target_never_reaches_a_rung_and_never_creates_a_profile() {
        // The security property, asserted as emptiness rather than as wording: the rung panics if
        // called, and no session directory may exist afterwards. Under the default policy, so the
        // metadata address is among the refusals.
        let (_temp, pool) = strict_pool(Arc::new(NeverRung));

        for url in [
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:9/",
            "http://localhost/admin",
        ] {
            let report = pool.fetch(&id("ses_one"), url).await;
            assert!(!report.succeeded(), "{url}");
            assert!(
                report.attempts.is_empty(),
                "nothing may be launched for {url}: {:?}",
                report.attempts
            );
            assert!(
                report
                    .stop_reason
                    .as_deref()
                    .unwrap()
                    .contains("not a fetchable target"),
                "{url}: {:?}",
                report.stop_reason
            );
        }

        assert_eq!(
            pool.session_count(),
            0,
            "a refused target must not leave a profile directory behind"
        );
    }

    #[tokio::test]
    async fn the_default_policy_refuses_loopback_and_allow_local_admits_it() {
        // The control for the test above: the refusal is a policy, not a blanket "refuse everything",
        // and the policy is what the pool was built with.
        let (_temp, root) = root();
        let strict = BrowserPool::new(root.clone(), Ladder::new(vec![ProfileRecordingRung::new()]));
        assert_eq!(strict.admission(), Admission::PublicInternet);

        let refused = strict.fetch(&id("ses_one"), "http://127.0.0.1:9/").await;
        assert!(refused.attempts.is_empty());
        assert_eq!(strict.session_count(), 0);

        let permissive = BrowserPool::new(root, Ladder::new(vec![ProfileRecordingRung::new()]))
            .with_admission(Admission::AllowLocal);
        let fetched = permissive
            .fetch(&id("ses_one"), "http://127.0.0.1:9/")
            .await;
        assert!(fetched.succeeded(), "{:?}", fetched.stop_reason);
        assert_eq!(permissive.session_count(), 1);
    }

    // ---------------------------------------------------------------------------------
    // The pool runs the ladder in the session's own profile
    // ---------------------------------------------------------------------------------

    #[tokio::test]
    async fn the_ladder_runs_inside_the_sessions_own_profile() {
        let rung = ProfileRecordingRung::new();
        let (_temp, pool) = pool_with(rung.clone());

        let report = pool.fetch(&id("ses_one"), "http://127.0.0.1:9/page").await;
        assert!(report.succeeded(), "{:?}", report.stop_reason);

        let expected = pool.session(&id("ses_one")).expect("a profile");
        assert_eq!(rung.seen(), vec![expected.dir().to_path_buf()]);
        assert_eq!(report.target, "http://127.0.0.1:9/page");
    }

    #[tokio::test]
    async fn two_sessions_fetching_concurrently_never_see_the_same_profile() {
        let rung = ProfileRecordingRung::new();
        let (_temp, pool) = pool_with(rung.clone());

        // Bound to locals: `&id(..)` in a `join!` borrows a temporary that is dropped at the end of
        // the macro's expansion, which does not compile.
        let session_a = id("ses_a");
        let session_b = id("ses_b");
        let (a, b) = tokio::join!(
            pool.fetch(&session_a, "http://127.0.0.1:9/a"),
            pool.fetch(&session_b, "http://127.0.0.1:9/b"),
        );

        assert!(a.succeeded() && b.succeeded());
        let seen = rung.seen();
        assert_eq!(seen.len(), 2);
        assert_ne!(
            seen[0], seen[1],
            "two concurrent sessions must not share a profile"
        );
        assert_eq!(pool.session_count(), 2);
    }

    #[tokio::test]
    async fn a_session_whose_profile_cannot_be_created_is_reported_rather_than_panicking() {
        let (_temp, pool) = pool_with(ProfileRecordingRung::new());

        let report = pool.fetch(&id("../escape"), "http://127.0.0.1:9/").await;
        assert!(!report.succeeded());
        assert!(report.attempts.is_empty());
        assert!(
            report.stop_reason.as_deref().unwrap().contains("../escape"),
            "the refusal must name the id: {:?}",
            report.stop_reason
        );
    }

    #[tokio::test]
    async fn a_token_in_a_pool_report_never_renders() {
        let (_temp, pool) = pool_with(ProfileRecordingRung::new());

        let report = pool
            .fetch(&id("ses_one"), "http://127.0.0.1:9/reset?token=SECRETVALUE")
            .await;

        assert!(report.succeeded());
        assert_eq!(report.target, "http://127.0.0.1:9/reset");
        assert!(
            !report.summary().contains("SECRETVALUE"),
            "{}",
            report.summary()
        );
        assert!(!format!("{report:?}").contains("SECRETVALUE"), "{report:?}");
    }

    #[test]
    fn the_pool_reports_its_shape_without_its_rungs() {
        let (_temp, root) = root();
        let pool = BrowserPool::new(root, Ladder::new(vec![]));
        let rendered = format!("{pool:?}");
        assert!(rendered.contains("BrowserPool"), "{rendered}");
        assert!(rendered.contains("admission: PublicInternet"), "{rendered}");
    }
}
