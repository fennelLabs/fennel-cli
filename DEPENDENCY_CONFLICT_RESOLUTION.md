# Dependency Conflict Resolution for fennel-cli v1.1.3

## Problem

When attempting to build fennel-cli v1.1.3 with the updated whiteflag-rust (whiteflagupdate2025 branch), we encounter a Rust dependency conflict:

```
error[E0308]: mismatched types
  --> schnorrkel::keys::MiniSecretKey type mismatch
```

### Root Cause

The issue occurs because:

1. **fennel-cli** (this project) needs:
   - `whiteflag-rust` (whiteflagupdate2025 branch) - uses newer dependencies with `schnorrkel v0.11.5`
   - `sp-keyring v44.0.0` - also uses newer substrate dependencies

2. **fennel-lib** (whiteflagupdatefennellib2025 branch) depends on:
   - `subxt v0.17.0` (very old version)
   - `sp-keyring v5.0.0` (very old version)

3. **Conflict**: `subxt v0.17.0` pulls in old substrate crates (`sp-core v4.0.0` and `v5.0.0`) which use `schnorrkel v0.9.1`, creating an incompatibility with the newer `schnorrkel v0.11.5` used by whiteflag-rust.

### Dependency Chain

```
fennel-cli v1.1.3
├── sp-keyring v44.0.0
│   └── sp-core v38.1.0 (uses schnorrkel v0.11.5 via substrate-bip39 v0.6.0)
├── whiteflag-rust (whiteflagupdate2025)
│   └── schnorrkel v0.11.5
└── fennel-lib (whiteflagupdatefennellib2025)
    ├── subxt v0.17.0
    │   └── sp-core v4.0.0 & v5.0.0 (use schnorrkel v0.9.1)
    └── sp-keyring v5.0.0
```

## Solution Options

### Option 1: Update fennel-lib Branch (RECOMMENDED)

Update the `whiteflagupdatefennellib2025` branch of fennel-lib to use newer substrate dependencies:

**Changes needed in fennel-lib/Cargo.toml:**
```toml
# OLD versions
subxt = "0.17.0"
sp-keyring = "5.0.0"

# NEW versions (change to)
subxt = "0.44.0"  # or latest compatible version
sp-keyring = "44.0.0"
```

**Note**: This will likely require code changes in fennel-lib to adapt to the new subxt API (major version change from 0.17 to 0.44).

### Option 2: Remove subxt/sp-keyring from fennel-lib

If fennel-lib doesn't actually need subxt or sp-keyring for the features used by fennel-cli, make them optional:

```toml
[dependencies]
subxt = { version = "0.17.0", optional = true }
sp-keyring = { version = "5.0.0", optional = true }

[features]
substrate = ["subxt", "sp-keyring"]
```

Then fennel-cli can depend on fennel-lib without the substrate features.

### Option 3: Fork fennel-lib Locally

Clone and modify fennel-lib locally:
```bash
cd /home/neurosx/DEVSPACE
git clone --branch whiteflagupdatefennellib2025 https://github.com/fennelLabs/fennel-lib.git fennel-lib-local
cd fennel-lib-local
# Update Cargo.toml as in Option 1
# Fix any code compatibility issues
```

Then update fennel-cli/Cargo.toml:
```toml
fennel-lib = { path = "../../fennel-lib-local", package = "fennel-lib" }
```

## Current Status

- ✅ whiteflag-rust updated to whiteflagupdate2025 branch (commit 373a916)
- ✅ fennel-cli Cargo.toml updated to use whiteflag-rust whiteflagupdate2025 branch  
- ✅ Rust dependencies resolved for whiteflag-rust and rsa crates
- ❌ **BLOCKED**: Cannot build due to fennel-lib substrate dependency conflict

## Next Steps

1. **Immediate**: Contact fennel-lib maintainers or create PR to update whiteflagupdatefennellib2025 branch dependencies
2. **Interim**: Use Option 3 (local fork) if immediate build is needed
3. **Testing**: Once built, deploy fennel-cli v1.1.3 to test Test message encoding

## Files Modified

- `/home/neurosx/DEVSPACE/fennel-deploy/fennel-cli/Cargo.toml`
  - Version bumped to 1.1.3
  - Changed whiteflag-rust to use local path (whiteflagupdate2025 branch)
  - Updated to use fennel-lib whiteflagupdatefennellib2025 branch
  - Added `resolver = "2"` for better dependency resolution
  - Upgraded sp-keyring from 5.0.0 → 44.0.0
  - Removed direct rsa dependency (using from fennel-lib)

- `/home/neurosx/DEVSPACE/fennel-deploy/fennel-cli/src/main.rs`
  - Updated imports to use RsaPublicKey from fennel-lib

- `/home/neurosx/DEVSPACE/fennel-deploy/fennel-cli/src/client/mod.rs`
  - Updated imports to use RsaPrivateKey, RsaPublicKey from fennel-lib

## Why This Matters

The Test message encoding fix in whiteflag-rust (commit 373a916) is critical:
- **Current State**: Free Text Test messages fail with "pseudoMessageCode expected 1 byte but was 42 bytes"
- **Root Cause**: Old fennel-cli uses whiteflag-rust with pseudoMessageCode at wrong index (14 instead of 7)
- **Fix**: whiteflagupdate2025 branch moves pseudoMessageCode to correct position per WhiteFlag spec
- **Impact**: Without this fix, any Test messages with body content (text, lat/long, etc.) will fail

## Test Results So Far

With fennel-api v1.0.8-test-messages-arm64 deployed:
- ✅ Test 1: Infrastructure Test message encode - **PASS**
- ✅ Test 2: Infrastructure Test message decode - **PASS**
- ❌ Test 3: Free Text Test message encode - **FAIL** (needs updated fennel-cli)
- ❌ Test 4: Free Text Test message decode - **FAIL** (needs updated fennel-cli)

Once fennel-cli v1.1.3 is deployed, all tests should pass.
