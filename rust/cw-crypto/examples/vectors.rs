//! Regenerates `vectors/format.json`. Run only when the format changes on purpose.
use std::path::Path;

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors");
    let standards: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("standards.json")).unwrap()).unwrap();
    let file = cw_crypto::vectors::generate(&standards).expect("vectors");
    std::fs::write(dir.join("format.json"), serde_json::to_string_pretty(&file).unwrap() + "\n").unwrap();
    let report = cw_crypto::vectors::check(
        &std::fs::read_to_string(dir.join("format.json")).unwrap(),
        &std::fs::read_to_string(dir.join("standards.json")).unwrap(),
    );
    println!("{report}");
}
