# GLib 0.18 security backport

The Linux Tauri/GTK3 stack requires GLib 0.18. A forced GLib 0.20 replacement is
incompatible. The workspace instead pins `glib`, `glib-sys`, `gobject-sys` and
`gio-sys` to gtk-rs-core commit
`ea720152f28e293ef4362ee844ee5cc499f32d2a`.

This is an **unmerged contributor backport**, not a maintained upstream release.
Its parent is the official 0.18 branch head
`42b9caf98e03ded086362d9653ca58fe94dc8658`. The entire upstream change is two
lines in `glib/src/variant_iter.rs`: declare `p` mutable and pass `&mut p` to
`g_variant_get_child`. This matches the accepted original fix for
[RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html).

Sources: [backport diff](https://github.com/gtk-rs/gtk-rs-core/commit/ea720152f28e293ef4362ee844ee5cc499f32d2a),
[closed PR #2009](https://github.com/gtk-rs/gtk-rs-core/pull/2009),
[original fix #1343](https://github.com/gtk-rs/gtk-rs-core/pull/1343).

Cargo audit and cargo-deny match the unchanged package version 0.18.5, so their
narrow advisory exception is conditional on this source pin. The regression
test in `apps/desktop/src-tauri/tests/glib_security.rs` exercises forward and backward
string-variant iteration in an optimized build. Keep the source-pin check and
optimized test passing; a version-based scanner exception alone proves nothing.

Reviewed 2026-11-16. Revisit on every Tauri update and remove these overrides
when its supported dependency graph contains the upstream fix. EOL GLib/GTK3
maintenance risk remains even with this specific unsoundness repaired.
