use std::path::PathBuf;

fn main() {
    let codegen_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_dir = codegen_dir.parent().expect("missing parent of codegen dir");
    let crate_dir = proto_dir.parent().expect("missing parent of proto dir");
    let out_dir = crate_dir.join("src").join("protobuf");

    let proto_file = proto_dir.join("csp-e2e.proto");

    let mut config = prost_build::Config::new();
    config.out_dir(&out_dir);
    config
        .compile_protos(&[proto_file], &[proto_dir])
        .expect("protobuf compilation failed");

    println!("Generated protobuf bindings in {}", out_dir.display());
}
