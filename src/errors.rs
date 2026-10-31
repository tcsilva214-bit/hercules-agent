//! Stable process exit codes + machine-readable error categories.
//! Frozen in CLI_AND_CONFIG_CONTRACT_V1.md and MODEL_GATEWAY_CONTRACT_V1.md.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrCat {
    Usage,              // 2
    ConfigMissing,      // 3
    ConfigMalformed,    // 4
    ConfigVersion,      // 5
    ConfigInvalidValue, // 6
    ProviderConnect,    // 10
    ProviderHttp,       // 11
    ModelUnknown,       // 12
    ResponseMalformed,  // 13
    IdentityMismatch,   // 14
    Timeout,            // 20
    Cancelled,          // 21
    Internal,           // 70
}

impl ErrCat {
    pub fn exit_code(self) -> i32 {
        match self {
            ErrCat::Usage => 2,
            ErrCat::ConfigMissing => 3,
            ErrCat::ConfigMalformed => 4,
            ErrCat::ConfigVersion => 5,
            ErrCat::ConfigInvalidValue => 6,
            ErrCat::ProviderConnect => 10,
            ErrCat::ProviderHttp => 11,
            ErrCat::ModelUnknown => 12,
            ErrCat::ResponseMalformed => 13,
            ErrCat::IdentityMismatch => 14,
            ErrCat::Timeout => 20,
            ErrCat::Cancelled => 21,
            ErrCat::Internal => 70,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            ErrCat::Usage => "USAGE",
            ErrCat::ConfigMissing => "CONFIG_MISSING",
            ErrCat::ConfigMalformed => "CONFIG_MALFORMED",
            ErrCat::ConfigVersion => "CONFIG_VERSION_UNSUPPORTED",
            ErrCat::ConfigInvalidValue => "CONFIG_INVALID_VALUE",
            ErrCat::ProviderConnect => "PROVIDER_CONNECT",
            ErrCat::ProviderHttp => "PROVIDER_HTTP",
            ErrCat::ModelUnknown => "MODEL_UNKNOWN",
            ErrCat::ResponseMalformed => "RESPONSE_MALFORMED",
            ErrCat::IdentityMismatch => "MODEL_IDENTITY_MISMATCH",
            ErrCat::Timeout => "TIMEOUT",
            ErrCat::Cancelled => "CANCELLED",
            ErrCat::Internal => "INTERNAL",
        }
    }
}

pub struct AppError {
    pub cat: ErrCat,
    pub detail: String,
}

impl AppError {
    pub fn new(cat: ErrCat, detail: impl Into<String>) -> Self {
        AppError {
            cat,
            detail: detail.into(),
        }
    }
    pub fn exit(self) -> ! {
        eprintln!(
            "HERCULES_AGENT_ERROR category={} detail={}",
            self.cat.label(),
            self.detail
        );
        std::process::exit(self.cat.exit_code());
    }
}
