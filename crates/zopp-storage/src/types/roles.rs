//! Role types for RBAC permissions.

use std::str::FromStr;

/// Role for RBAC permissions
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    Admin,
    Write,
    Read,
}

/// Error type for parsing Role from string
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRoleError(pub String);

impl std::fmt::Display for ParseRoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid role: {}", self.0)
    }
}

impl std::error::Error for ParseRoleError {}

impl FromStr for Role {
    type Err = ParseRoleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Role::Admin),
            "write" => Ok(Role::Write),
            "read" => Ok(Role::Read),
            _ => Err(ParseRoleError(s.to_string())),
        }
    }
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Write => "write",
            Role::Read => "read",
        }
    }

    /// Check if this role has at least the permissions of another role
    pub fn includes(&self, other: &Role) -> bool {
        match self {
            Role::Admin => true, // Admin includes all permissions
            Role::Write => matches!(other, Role::Write | Role::Read),
            Role::Read => matches!(other, Role::Read),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_includes_admin() {
        // Admin includes all roles
        assert!(Role::Admin.includes(&Role::Admin));
        assert!(Role::Admin.includes(&Role::Write));
        assert!(Role::Admin.includes(&Role::Read));
    }

    #[test]
    fn test_role_includes_write() {
        // Write includes Write and Read, but not Admin
        assert!(!Role::Write.includes(&Role::Admin));
        assert!(Role::Write.includes(&Role::Write));
        assert!(Role::Write.includes(&Role::Read));
    }

    #[test]
    fn test_role_includes_read() {
        // Read only includes Read
        assert!(!Role::Read.includes(&Role::Admin));
        assert!(!Role::Read.includes(&Role::Write));
        assert!(Role::Read.includes(&Role::Read));
    }

    #[test]
    fn test_role_as_str() {
        assert_eq!(Role::Admin.as_str(), "admin");
        assert_eq!(Role::Write.as_str(), "write");
        assert_eq!(Role::Read.as_str(), "read");
    }

    #[test]
    fn test_role_parse() {
        assert_eq!("admin".parse::<Role>().unwrap(), Role::Admin);
        assert_eq!("write".parse::<Role>().unwrap(), Role::Write);
        assert_eq!("read".parse::<Role>().unwrap(), Role::Read);
    }

    #[test]
    fn test_role_parse_invalid() {
        assert!("invalid".parse::<Role>().is_err());
        assert!("Admin".parse::<Role>().is_err()); // Case sensitive
        assert!("ADMIN".parse::<Role>().is_err());
        assert!("".parse::<Role>().is_err());
    }

    #[test]
    fn test_role_roundtrip() {
        for role in [Role::Admin, Role::Write, Role::Read] {
            let s = role.as_str();
            let parsed: Role = s.parse().unwrap();
            assert_eq!(role, parsed);
        }
    }

    #[test]
    fn test_role_is_copy() {
        let role = Role::Admin;
        let copied = role; // Copy, not move
        assert_eq!(role, copied); // Original still valid
    }

    #[test]
    fn test_parse_role_error_display() {
        let err = ParseRoleError("unknown".to_string());
        assert!(err.to_string().contains("unknown"));
    }
}
