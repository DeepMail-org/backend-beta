use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Analyst,
    Admin,
    Superadmin,
}

impl UserRole {
    fn level(&self) -> u8 {
        match self {
            UserRole::Analyst => 0,
            UserRole::Admin => 1,
            UserRole::Superadmin => 2,
        }
    }

    pub fn has_at_least(&self, minimum: &UserRole) -> bool {
        self.level() >= minimum.level()
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::Analyst => write!(f, "analyst"),
            UserRole::Admin => write!(f, "admin"),
            UserRole::Superadmin => write!(f, "superadmin"),
        }
    }
}

impl std::str::FromStr for UserRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "analyst" => Ok(UserRole::Analyst),
            "admin" => Ok(UserRole::Admin),
            "superadmin" => Ok(UserRole::Superadmin),
            other => Err(format!("Unknown role: {other}")),
        }
    }
}
