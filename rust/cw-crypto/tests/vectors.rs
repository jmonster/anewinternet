//! The native run of the cross-target vectors.
#[test]
fn format_and_standard_vectors() {
    let report =
        cw_crypto::vectors::check(include_str!("../vectors/format.json"), include_str!("../vectors/standards.json"));
    assert_eq!(report["failures"], serde_json::json!([]), "{report}");
    println!("native {report}");
}
