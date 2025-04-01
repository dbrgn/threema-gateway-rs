# Fuzz Tests for threema-gateway-rs

To run these, install [afl.rs](https://github.com/rust-fuzz/afl.rs):

    cargo install -f cargo-afl

Then enter the directory of a fuzz target. Build:

    cargo afl build

...then run. For example:

    cargo afl fuzz -i in -o out target/debug/target-parse-incoming-message

When a crash is found, you can reproduce it:

    cargo afl run url-fuzz-target < out/default/crashes/<crashfile>

For more information, see:

- https://github.com/rust-fuzz/afl.rs
- https://rust-fuzz.github.io/book/afl.html
