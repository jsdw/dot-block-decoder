# dot-block-decoder

A small, low level 100% Rust block decoding example on decoding and printing block information from Polkadot, all the way from genesis.

Basic usage:

```
cargo run -- --block-number 1234
```

This is essentially a distilled, simplified version of https://github.com/jsdw/polkadot-historic-decoding-example, using
modern RPCs and so on.