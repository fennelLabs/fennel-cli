#!/usr/bin/env bash

rustup update stable
rustup override set stable

cargo update
cargo clean
cargo build
rm -rf Private.key Public.key identity.db message.db test.txt
cargo test -- --test-threads 1
cargo doc

cargo build --release
cargo doc --release
