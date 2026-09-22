//! Eval runs: one job row owning many trial rows, so `hx eval results` can compare runs later.
//!
//! ## Why the job row keeps totals
//!
//! Listing jobs must not sum trials per row: a job with thousands of trials would make the
//! results list pay for every trial on every render. So the job row carries `trials`, `passed`,
//! and `total_cost`, maintained by [`Store::insert_eval_trial`] in the same transaction as the
//! trial insert. A job row is therefore a cache that trusts its writer — which is this module,
//! the only code that writes either table.

use crate::schema::fail;
use crate::session::stamp;
use crate::store::Store;
use chrono::Utc;
use hx_core::error::{HxError, Result};
use hx_core::ids::{EvalJobId, EvalTrialId};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

/// One eval run over a dataset: what was asked, and the running score.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvalJob {
    pub id: EvalJobId,
    pub dataset: String,
    pub role: String,
    pub task: String,
    pub trials: i64,
    pub passed: i64,
    /// The sum of every trial's cost, in dollars the price table claimed rather than invoiced —
    /// the same honesty as the usage rows.
    pub total_cost: f64,
    pub created_at: String,
}

/// What a caller supplies to start an eval run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewEvalJob {
    pub dataset: String,
    pub role: String,
    pub task: String,
}

/// One task attempt within an eval job.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvalTrial {
    pub id: EvalTrialId,
    pub job_id: EvalJobId,
    /// The session that ran this attempt, if it ran in one. `None` for a trial that never got
    /// far enough to start a session — a setup failure, say — which still counts as a trial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub task: String,
    pub passed: bool,
    pub reason: String,
    pub duration_ms: i64,
    pub tokens_in: i64,
    pub tokens_out: i64,
    pub cost_usd: f64,
    pub created_at: String,
}

/// What a caller supplies to record one attempt.
#[derive(Clone, Debug, PartialEq)]
pub struct NewEvalTrial {
    pub job_id: EvalJobId,
    pub session_id: Option<String>,
    pub task: String,
    pub passed: bool,
    pub reason: String,
    pub duration_ms: i64,
    pub tokens_in: i64,
    pub tokens_out: i64,
    pub cost_usd: f64,
}

impl Store {
    /// Start an eval run. The id is minted here, not by the caller, for the same reason session
    /// ids are: a client that could choose one could collide with a run it has never seen.
    pub fn insert_eval_job(&self, new: &NewEvalJob) -> Result<EvalJob> {
        let job = EvalJob {
            id: EvalJobId::new(),
            dataset: new.dataset.clone(),
            role: new.role.clone(),
            task: new.task.clone(),
            trials: 0,
            passed: 0,
            total_cost: 0.0,
            created_at: stamp(Utc::now()),
        };

        self.with_tx(|tx| {
            tx.execute(
                "INSERT INTO eval_jobs (id, dataset, role, task, trials, passed, total_cost, \
                 created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    job.id.as_str(),
                    job.dataset,
                    job.role,
                    job.task,
                    job.trials,
                    job.passed,
                    job.total_cost,
                    job.created_at,
                ],
            )
            .map_err(|err| fail("could not record the eval job", err))?;
            Ok(())
        })?;

        Ok(job)
    }

    /// Record one attempt and roll its outcome into the parent job, atomically.
    ///
    /// The trial insert and the job's `trials` / `passed` / `total_cost` bump share one
    /// transaction: a trial that exists without being counted — or counted without existing —
    /// would make `hx eval results` lie, and the lie would look like data.
    pub fn insert_eval_trial(&self, new: &NewEvalTrial) -> Result<EvalTrial> {
        let trial = EvalTrial {
            id: EvalTrialId::new(),
            job_id: new.job_id.clone(),
            session_id: new.session_id.clone(),
            task: new.task.clone(),
            passed: new.passed,
            reason: new.reason.clone(),
            duration_ms: new.duration_ms,
            tokens_in: new.tokens_in,
            tokens_out: new.tokens_out,
            cost_usd: new.cost_usd,
            created_at: stamp(Utc::now()),
        };

        self.with_tx(|tx| {
            // Checked first so that recording against a deleted or mistyped job id is a
            // `NotFound` the caller can act on, rather than a foreign-key failure from
            // inside SQLite — the same reason session writes go through `touch`.
            let exists: Option<String> = tx
                .query_row(
                    "SELECT id FROM eval_jobs WHERE id = ?1",
                    [trial.job_id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|err| fail("could not read the eval job", err))?;
            if exists.is_none() {
                return Err(HxError::NotFound(format!(
                    "eval job {}",
                    trial.job_id.as_str()
                )));
            }

            tx.execute(
                "INSERT INTO eval_trials (id, job_id, session_id, task, passed, reason, \
                 duration_ms, tokens_in, tokens_out, cost_usd, created_at) VALUES (?1, ?2, ?3, \
                 ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    trial.id.as_str(),
                    trial.job_id.as_str(),
                    trial.session_id,
                    trial.task,
                    i64::from(trial.passed),
                    trial.reason,
                    trial.duration_ms,
                    trial.tokens_in,
                    trial.tokens_out,
                    trial.cost_usd,
                    trial.created_at,
                ],
            )
            .map_err(|err| fail("could not record the eval trial", err))?;

            let bumped = tx
                .execute(
                    "UPDATE eval_jobs SET trials = trials + 1, passed = passed + ?2, total_cost \
                     = total_cost + ?3 WHERE id = ?1",
                    params![
                        trial.job_id.as_str(),
                        i64::from(trial.passed),
                        trial.cost_usd,
                    ],
                )
                .map_err(|err| fail("could not roll the trial into its eval job", err))?;
            if bumped == 0 {
                // Unreachable after the existence check above — same transaction, no one else
                // can delete the job under us — but a silently uncounted trial would make
                // `hx eval results` lie, so the update is verified rather than assumed.
                return Err(HxError::NotFound(format!(
                    "eval job {}",
                    trial.job_id.as_str()
                )));
            }
            Ok(())
        })?;

        Ok(trial)
    }

    /// Every eval run, newest first — what `hx eval results` lists.
    pub fn list_eval_jobs(&self) -> Result<Vec<EvalJob>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, dataset, role, task, trials, passed, total_cost, created_at FROM \
                 eval_jobs ORDER BY created_at DESC, rowid DESC",
            )
            .map_err(|err| fail("could not list the eval jobs", err))?;
        let jobs = stmt
            .query_map([], read_job)
            .map_err(|err| fail("could not list the eval jobs", err))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|err| fail("could not read an eval job", err))?;
        Ok(jobs)
    }

    /// Every trial of one run, oldest first — the order the run produced them in.
    pub fn trials_for_job(&self, job_id: &EvalJobId) -> Result<Vec<EvalTrial>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, job_id, session_id, task, passed, reason, duration_ms, tokens_in, \
                 tokens_out, cost_usd, created_at FROM eval_trials WHERE job_id = ?1 ORDER BY \
                 created_at ASC, rowid ASC",
            )
            .map_err(|err| fail("could not read the eval trials", err))?;
        let trials = stmt
            .query_map([job_id.as_str()], read_trial)
            .map_err(|err| fail("could not read the eval trials", err))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|err| fail("could not read an eval trial", err))?;
        Ok(trials)
    }
}

fn read_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<EvalJob> {
    Ok(EvalJob {
        id: EvalJobId::from_raw(row.get::<_, String>(0)?),
        dataset: row.get(1)?,
        role: row.get(2)?,
        task: row.get(3)?,
        trials: row.get(4)?,
        passed: row.get(5)?,
        total_cost: row.get(6)?,
        created_at: row.get(7)?,
    })
}

fn read_trial(row: &rusqlite::Row<'_>) -> rusqlite::Result<EvalTrial> {
    // Stored as 0/1: SQLite has no boolean, and reading an INTEGER column into a `bool`
    // directly is a type error rather than a conversion.
    let passed: i64 = row.get(4)?;
    Ok(EvalTrial {
        id: EvalTrialId::from_raw(row.get::<_, String>(0)?),
        job_id: EvalJobId::from_raw(row.get::<_, String>(1)?),
        session_id: row.get(2)?,
        task: row.get(3)?,
        passed: passed != 0,
        reason: row.get(5)?,
        duration_ms: row.get(6)?,
        tokens_in: row.get(7)?,
        tokens_out: row.get(8)?,
        cost_usd: row.get(9)?,
        created_at: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::in_memory().expect("in-memory store")
    }

    fn job() -> NewEvalJob {
        NewEvalJob {
            dataset: "shell-basics".to_string(),
            role: "coder".to_string(),
            task: "fix the build".to_string(),
        }
    }

    fn trial(job_id: &EvalJobId, task: &str, passed: bool, cost_usd: f64) -> NewEvalTrial {
        NewEvalTrial {
            job_id: job_id.clone(),
            session_id: Some("ses_1".to_string()),
            task: task.to_string(),
            passed,
            reason: if passed { "ok" } else { "timed out" }.to_string(),
            duration_ms: 1_200,
            tokens_in: 100,
            tokens_out: 50,
            cost_usd,
        }
    }

    #[test]
    fn trials_roll_their_outcome_into_the_job() {
        let store = store();
        let job = store.insert_eval_job(&job()).unwrap();
        assert_eq!((job.trials, job.passed), (0, 0));
        assert_eq!(job.total_cost, 0.0);
        assert!(job.id.as_str().starts_with("evj_"));

        let first = store
            .insert_eval_trial(&trial(&job.id, "one", true, 0.25))
            .unwrap();
        assert!(first.id.as_str().starts_with("evt_"));
        assert!(first.passed);
        let second = store
            .insert_eval_trial(&trial(&job.id, "two", false, 1.5))
            .unwrap();
        assert!(!second.passed);

        let jobs = store.list_eval_jobs().unwrap();
        assert_eq!(jobs.len(), 1, "list_eval_jobs returns the job");
        assert_eq!(jobs[0].id, job.id);
        assert_eq!(jobs[0].trials, 2);
        assert_eq!(jobs[0].passed, 1);
        assert!(
            (jobs[0].total_cost - 1.75).abs() < 1e-9,
            "total_cost is the sum: {}",
            jobs[0].total_cost
        );

        let trials = store.trials_for_job(&job.id).unwrap();
        assert_eq!(trials.len(), 2);
        assert_eq!(trials[0].task, "one", "oldest first");
        assert_eq!(trials[1].task, "two");
        assert_eq!(trials[0].job_id, job.id);
    }

    #[test]
    fn list_puts_the_newest_job_first() {
        let store = store();
        let first = store.insert_eval_job(&job()).unwrap();
        let second = store.insert_eval_job(&job()).unwrap();

        let listed = store.list_eval_jobs().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, second.id);
        assert_eq!(listed[1].id, first.id);
    }

    #[test]
    fn a_trial_for_a_missing_job_is_not_found() {
        let store = store();
        let missing = EvalJobId::from_raw("evj_nope");
        let err = store
            .insert_eval_trial(&trial(&missing, "one", true, 0.1))
            .unwrap_err();
        assert!(matches!(err, HxError::NotFound(_)), "{err}");
        assert!(store.trials_for_job(&missing).unwrap().is_empty());
    }
}
