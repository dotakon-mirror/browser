## Prerequisites

You need [Node.js](https://nodejs.org/), [Rust](https://www.rust-lang.org/), and [`wasm-bindgen-cli`](https://crates.io/crates/wasm-bindgen-cli).

## Building and Running

The following assumes the root of this repo is the current working directory.

To build the Rust engine, first move into the `lib` subdirectory and then use `cargo`:

```sh
browser$ cd lib
browser/lib$ cargo build --target wasm32-unknown-unknown --release
```

Optionally run the tests (**before** `cargo build`):

```sh
browser/lib$ cargo test
```

Then generate the JavaScript bindings:

```sh
browser/lib$ wasm-bindgen target/wasm32-unknown-unknown/release/lib.wasm --out-dir ../lib-bindings/ --target bundler
```

Now you can move back to the root and run the full app:

```sh
browser/lib$ cd ..
browser$ npm start
```

The final native binary is built with:

```sh
browser$ npm run package
```
