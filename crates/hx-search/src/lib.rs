//! Web search: a fan-out over interchangeable backends with rank fusion.
//!
//! ## Why several backends rather than one
//!
//! Keyless scraping backends break. Constantly — bot detection changes, markup changes, an
//! endpoint gets retired. A harness that hard-codes one is a harness whose `web_search` tool
//! silently returns nothing for a week before anyone notices. So the design assumes breakage:
//! every backend is an independent [`SearchBackend`], the aggregator tolerates failures, and the
//! report tells the caller which backends actually answered.
//!
//! ## Why Reciprocal Rank Fusion
//!
//! Each backend ranks by its own notion of score, and scraped backends have no scores at all. RRF
//! sidesteps the incomparable-scores problem by using only **rank**:
//!
//! ```text
//! score(d) = sum over backends of  1 / (k + rank_of_d_in_that_backend)
//! ```
//!
//! with `k = 60` from Cormack, Clarke & Buettcher (2009). Ranks are comparable across engines;
//! scores are not. A document that several engines independently put near the top wins, which is
//! exactly the signal worth trusting — and it needs no tuning.
//!
//! ## SearXNG as the force multiplier
//!
//! SearXNG fronts roughly seventy engines (Google, Bing, Brave, Mojeek, Marginalia, arXiv,
//! Wikipedia, GitHub, …) behind one JSON API. Pointing `search.backends` at a self-hosted SearXNG
//! satisfies most of "all the free stuff" with a single backend far more robust than scraping
//! each engine directly. The direct keyless scrapers here cover the case where none is available.

pub mod aggregate;
pub mod backend;
pub mod backends;
pub mod extract;
pub mod cache;
pub mod types;

pub use aggregate::{fanout, BackendFailure, SearchReport, DEFAULT_BACKEND_TIMEOUT};
pub use backend::{
    BackendKind, BackendRegistry, SearchBackend, SearchError, KEYLESS_BACKENDS, KNOWN_BACKENDS,
};
pub use backends::{
    BraveBackend, DuckDuckGoBackend, GoogleCseBackend, HnAlgoliaBackend, MarginaliaBackend,
    MojeekBackend, SearxngBackend, WikipediaBackend,
};
pub use extract::{
    looks_like_markup, Extracted, ExtractionRung, FetchedPage, Ladder, PlainRung, ReadabilityRung,
    Rung, MAIN_SHARE, MIN_MAIN_CHARS,
};
pub use cache::{cache_key, CacheOutcome, Clock, SystemClock, UrlCache};
pub use types::{
    canonicalize_url, fuse, host_matches, FusedResult, Recency, SearchQuery, SearchResult, RRF_K,
};
