#!/bin/bash
apt-get update
apt-get install unzip curl build-essential protobuf-compiler -y
apt-get install clang libclang-dev libclang1 llvm llvm-dev clang-tools -y
apt-get install pkg-config libssl-dev -y
apt-get upgrade -y

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

rustup default stable
rustup update stable