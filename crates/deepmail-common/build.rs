fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Protobuf / gRPC compilation via tonic-build ─────────────────────
    //
    // Proto files live in crates/deepmail-common/proto/.
    // Generated code lands in OUT_DIR and is included via tonic::include_proto!().

    // Proto files to compile — add new .proto files here as services grow.
    let protos: &[&str] = &["proto/dkim.proto", "proto/homograph.proto", "proto/billing.proto"];

    // Include path: our own proto/ directory (for cross-file imports).
    // tonic-build automatically resolves google.protobuf well-known types
    // via the bundled prost-types crate.
    let includes: &[&str] = &["proto"];

    tonic_build::configure()
        // Use prost-types for google.protobuf.Timestamp (default behavior).
        .compile_well_known_types(false)
        // Build server code (for deepmail-dkim service implementation).
        .build_server(true)
        // Build client code (for deepmail-ioc and other callers).
        .build_client(true)
        .compile_protos(protos, includes)?;

    // Re-run if any proto file changes.
    println!("cargo:rerun-if-changed=proto/");

    Ok(())
}
