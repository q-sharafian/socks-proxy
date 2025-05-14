fn main() {
  // Tell cargo to tell rustc to link the system shared library `req_processor`.
  // Adjust the path to where your `libreq_processor.so` file is located.
  // This could be an absolute path or a relative path from the root of this crate.
  // For example, if it's in a `libs` directory at the root of your project:
  // println!("cargo:rustc-link-search=native=./libs");
  // Or an absolute path:
  println!("cargo:rustc-link-search=native=/home/mohammad/Development/req-processor/target/release/");

  // This line is implicitly handled by `#[link(name = "req_processor", kind = "dylib")]`
  // but explicitly stating the kind can sometimes be useful for clarity or if
  // `kind` isn't specified in the extern block.
  // However, with `kind = "dylib"` in your `extern` block, this specific line
  // in build.rs might be redundant for just linking, but `rustc-link-search` is crucial.
  // println!("cargo:rustc-link-lib=dylib=req_processor");
}