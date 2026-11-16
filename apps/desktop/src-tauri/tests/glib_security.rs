#![cfg(target_os = "linux")]

use glib::variant::ToVariant as _;

#[test]
fn optimized_string_variant_iteration_uses_fixed_backport() {
    let v = ["zero", "one", "two", "three"].to_variant();
    let mut it = v.array_iter_str().unwrap();
    assert_eq!(it.next(), Some("zero"));
    assert_eq!(it.next_back(), Some("three"));
    assert_eq!(it.nth(1), Some("two"));
    assert_eq!(v.array_iter_str().unwrap().nth_back(1), Some("two"));
    assert_eq!(v.array_iter_str().unwrap().last(), Some("three"));
}

#[test]
fn advisory_exception_requires_the_reviewed_source_pin() {
    let lock = include_str!("../../../../Cargo.lock");
    for name in ["glib", "glib-sys", "gobject-sys", "gio-sys"] {
        let packages: Vec<_> = lock
            .split("[[package]]")
            .filter(|p| p.lines().any(|l| l == format!("name = \"{name}\"")))
            .collect();
        assert_eq!(packages.len(), 1, "{name} must have exactly one source");
        assert!(packages[0].contains("source = \"git+https://github.com/gtk-rs/gtk-rs-core?rev=ea720152f28e293ef4362ee844ee5cc499f32d2a#ea720152f28e293ef4362ee844ee5cc499f32d2a\""));
    }
}
