# fennel-cli

To set up the CLI and find information on how to use the CLI, run

```bash
$ ./scripts/setup.sh
$ cargo run
$ target/debug/fennel-cli help
```

To run the local cryptography RPC, run

```bash
$ ./scripts/setup.sh
$ cargo run --bin fennel-cli -- start-rpc
```

To interact with IPFS:

**Add file**
```bash
$ cargo run --bin fennel-ipfs -- add-file ./test.txt
```

Returns a CID for use with the other two commands.

**Get file**
```bash
$ cargo run --bin fennel-ipfs -- get-file <cid>
```

Returns the content of the file at the given CID.

**Delete file**
```bash
$ cargo run --bin fennel-ipfs -- delete-file <cid>
```

# Testing Guide

```bash
sh scripts/build-test.sh
```
