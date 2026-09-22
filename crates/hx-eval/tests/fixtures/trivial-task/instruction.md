# Trivial task

Do nothing. There is nothing to change and nothing to build.

The verifier (`tests/check.sh`) always passes; this task exists so the trial
runner has a canary that exercises spawn → stage → agent → verify → persist
without needing a real environment.
