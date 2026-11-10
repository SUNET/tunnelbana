# PyO3 0.30 compatibility patch

Source: the published `pythonize` 0.29.0 crate from
<https://crates.io/crates/pythonize/0.29.0>.
Its registry checksum is
`6ec376e1216e0c929a74964ce2020012a1a39f32d80e78aa688721219ea7fb89`.
The original MIT license, README, source and tests are retained.

Upstream 0.29.0 requires PyO3 0.29. Tunnelbana uses the same conversion
implementation with its normal and development PyO3 dependency requirements
changed to `0.30.1`. No conversion behavior is intentionally changed.

The workspace excludes this vendored crate from its members and selects it
through `[patch.crates-io]`. This keeps one PyO3/CPython FFI implementation
throughout the workspace, including arbitrary-precision JSON conversion.

Remove this directory, the workspace exclusion and the patch when an upstream
Pythonize release supports PyO3 0.30, then update the exact Pythonize pin.

Run the retained upstream tests with:

```sh
cargo test --manifest-path vendor/pythonize/Cargo.toml --all-features --target-dir target
```
