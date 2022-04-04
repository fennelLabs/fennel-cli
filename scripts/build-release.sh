#!/usr/bin/env bash

rustup update stable
rustup override set stable

cargo build
cargo test
cargo doc

cargo build --release
cargo doc --release
