//! Typed identifiers. Newtypes rather than bare `String` so that a `HostId` can never be
//! passed where a `SandboxId` is expected — a class of bug that is genuinely common in
//! harnesses that pass ids around as strings.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! define_id {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Mint a fresh random id.
            pub fn new() -> Self {
                Self(format!("{}_{}", $prefix, Uuid::new_v4().simple()))
            }

            /// Wrap an existing string (e.g. one read back from the database).
            pub fn from_raw(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
    };
}

define_id!(
    SessionId,
    "ses",
    "A conversation. Survives client disconnects — it lives in `hxd`."
);
define_id!(
    AgentId,
    "agt",
    "One running agent (or subagent) within a session."
);
define_id!(MessageId, "msg", "A single message in the transcript.");
define_id!(
    ToolCallId,
    "tc",
    "A tool invocation, used to correlate call and result."
);
define_id!(SandboxId, "sbx", "An isolated execution environment.");
define_id!(
    VolumeId,
    "vol",
    "A persistent workspace volume, outliving its sandbox."
);
define_id!(
    HostId,
    "hst",
    "A machine in the host registry (local, SSH, or WinRM)."
);
define_id!(ProviderId, "prv", "A configured model provider.");
define_id!(
    CredentialId,
    "cred",
    "One credential within a provider's pool."
);
define_id!(PoolId, "pool", "A logical model pool that roles draw from.");
define_id!(ConnectorId, "con", "A chat platform adapter.");
define_id!(
    CapabilityId,
    "cap",
    "A granted capability, for audit correlation."
);
define_id!(ApprovalId, "apr", "A pending human approval request.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_unique_and_prefixed() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
        assert!(a.as_str().starts_with("ses_"));
    }

    #[test]
    fn ids_round_trip_through_json_as_bare_strings() {
        let id = HostId::from("hst_abc");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"hst_abc\"");
        let back: HostId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn distinct_id_types_do_not_compare_equal_by_accident() {
        // Compile-time property, asserted here as documentation.
        let s = SessionId::from_raw("x");
        assert_eq!(s.as_str(), "x");
    }
}
