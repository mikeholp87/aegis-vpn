use std::collections::BTreeSet;

#[test]
fn main_webview_has_only_approved_command_permissions() {
    let capability: serde_json::Value =
        serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
    assert_eq!(capability["windows"], serde_json::json!(["main"]));
    assert!(capability.get("remote").is_none());

    let manifest = include_str!("../build.rs")
        .split("fn main()")
        .next()
        .unwrap();
    let handlers = include_str!("../src/lib.rs");
    let mut expected = BTreeSet::from([
        "core:event:allow-listen".to_owned(),
        "core:event:allow-unlisten".to_owned(),
    ]);
    for line in manifest.lines() {
        if let Some(command) = line
            .trim()
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix("\","))
        {
            assert!(handlers.contains(&format!("commands::{command},")));
            expected.insert(format!("allow-{}", command.replace('_', "-")));
        }
    }
    let actual = capability["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
}
