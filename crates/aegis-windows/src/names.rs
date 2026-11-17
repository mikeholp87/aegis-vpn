//! Naming rules for tunnels Aegis owns on Windows.
//!
//! The official tunnel service names its service `WireGuardTunnel$<name>` and
//! uses `<name>` for the Wintun adapter. WireGuard limits `<name>` to 32 of
//! `[a-zA-Z0-9_=+.-]`, and Windows service names are case-insensitive, so the
//! name is `aegis-` plus the first 24 hex digits of the profile id (96 bits).
//! Ownership is decided only by this exact shape (AGENTS.md rule 7).

use aegis_core::ProfileId;

pub const PREFIX: &str = "aegis-";
const ID_DIGITS: usize = 24;
pub const SERVICE_PREFIX: &str = "WireGuardTunnel$";

pub fn tunnel_name(id: ProfileId) -> String {
    format!("{PREFIX}{}", &id.0.simple().to_string()[..ID_DIGITS])
}

pub fn service_name(id: ProfileId) -> String {
    format!("{SERVICE_PREFIX}{}", tunnel_name(id))
}

/// True for a tunnel name Aegis could have created (any id).
pub fn is_owned_tunnel_name(name: &str) -> bool {
    name.strip_prefix(PREFIX).is_some_and(|rest| {
        rest.len() == ID_DIGITS
            && rest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// True for a Windows service name Aegis could have created.
pub fn is_owned_service_name(name: &str) -> bool {
    name.strip_prefix(SERVICE_PREFIX)
        .is_some_and(is_owned_tunnel_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_fit_wireguard_limits_and_are_owned() {
        let id = ProfileId::new();
        let t = tunnel_name(id);
        assert!(t.len() <= 32, "{t}");
        assert!(t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        assert!(is_owned_tunnel_name(&t));
        assert!(is_owned_service_name(&service_name(id)));
    }

    #[test]
    fn foreign_names_are_not_owned() {
        for n in [
            "wg0",
            "aegis-",
            "aegis-xyz",
            "aegis-0123456789abcdef0123456",   // 23 digits
            "aegis-0123456789abcdef012345678", // 25 digits
            "AEGIS-0123456789abcdef01234567",
            "aegis-0123456789ABCDEF01234567",
        ] {
            assert!(!is_owned_tunnel_name(n), "{n}");
        }
        assert!(!is_owned_service_name("WireGuardTunnel$office"));
        assert!(!is_owned_service_name("aegis-0123456789abcdef01234567"));
    }

    #[test]
    fn different_profiles_get_different_names() {
        assert_ne!(tunnel_name(ProfileId::new()), tunnel_name(ProfileId::new()));
    }
}
