//! Build script for threema-gateway crate.

fn main() {
    // Compile protobuf messages
    prost_build::compile_protos(&["protobuf/csp-e2e.proto"], &["protobuf/"])
        .expect("protobuf compilation failed");
}
