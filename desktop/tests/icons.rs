//! The icons are the Android app's mark, unmodified apart from colour (NOTICE says so): the path
//! data must match `ic_logo.xml` exactly, or NOTICE would be wrong.

use std::fs;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn attr<'a>(text: &'a str, key: &str) -> &'a str {
    let at = text.find(key).unwrap_or_else(|| panic!("no {key}"));
    let rest = &text[at + key.len()..];
    &rest[..rest.find('"').unwrap()]
}

#[test]
fn every_icon_carries_the_androids_glyph_path() {
    let xml = fs::read_to_string(root().join("app/src/main/res/drawable/ic_logo.xml")).unwrap();
    let glyph = attr(&xml, "android:pathData=\"");
    assert!(glyph.len() > 1000);
    let dir = root().join("desktop/data/icons");
    let mut colours = std::collections::HashSet::new();
    let mut n = 0;
    for e in fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        let svg = fs::read_to_string(&p).unwrap();
        assert_eq!(attr(&svg, " d=\""), glyph, "{}", p.display());
        assert!(svg.contains("viewBox=\"0 0 960 960\""), "{}", p.display());
        colours.insert(attr(&svg, "fill=\"").to_string());
        n += 1;
    }
    assert_eq!(n, 5, "the app icon and one per state");
    assert_eq!(
        colours.len(),
        4,
        "the app icon shares the Ready colour, the states differ: {colours:?}"
    );
}

#[test]
fn notice_covers_the_desktop_icons() {
    let notice = fs::read_to_string(root().join("NOTICE")).unwrap();
    assert!(
        notice.contains("desktop/data/icons"),
        "NOTICE must list the desktop icons"
    );
    assert!(notice.contains("Apache License"));
}
