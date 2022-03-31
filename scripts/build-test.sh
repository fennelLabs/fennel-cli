#!/bin/bash
rm -rf Private.key Public.key identity.db message.db
cargo test -- --test-threads 1
