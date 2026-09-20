//! The interactive Chromium rung (CDP).
//!
//! Drives headless Chromium over the Chrome DevTools Protocol (CDP), enforcing target
//! admission on every request via CDP `Fetch.enable` request interception before bytes
//! reach the wire, and reaping the browser child process on every exit path.
