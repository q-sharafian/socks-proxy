fn main() -> Result<(), Box<dyn std::error::Error>> {
  let proto_path = "proto/api/net_sentinel.proto";
  tonic_build::compile_protos(&proto_path)?;

  Ok(())
  // This line is implicitly handled by `#[link(name = "req_processor", kind = "dylib")]`
  // but explicitly stating the kind can sometimes be useful for clarity or if
  // `kind` isn't specified in the extern block.
  // However, with `kind = "dylib"` in your `extern` block, this specific line
  // in build.rs might be redundant for just linking, but `rustc-link-search` is crucial.
  // println!("cargo:rustc-link-lib=dylib=req_processor");
}
