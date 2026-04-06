# Threema Gateway SDK

General hints:

- You MUST read `README.md` for a general overview.
- You MUST read `src/lib.rs` to see the entry point into the library.

## Conventions

### Rust

Imports:

- Use merged imports
- Group imports using the "std / third party / first party (`super::` /
  `crate::`)" convention
- Don't use `std::*` directly, instead import the corresponding modules or
  types at the top level
- Don't use `super::*` imports (except in test modules), instead use `crate::`
  imports

Testing:

- When adding multiple unit tests for a function, struct or enum, wrap them in
  a dedicated module named after that unit. For example, when a function is
  called `check_foo`, the test path should be `tests::check_foo::a_test` and
  `tests::check_foo::another_test`.
- When importing types that are only used for tests, import them inside the
  `tests` module and do not use `#[cfg(test)]` on top level

Other:

- Sort dependencies (in `Cargo.toml`) and imports alphabetically
- Check if code compiles with `cargo check`
- Lint code with `cargo clippy`
- At the end, when everything else works fine, ALWAYS format code with rustfmt
  through `cargo fmt`
