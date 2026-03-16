# Seed-Recovery-Framework-for-MPCitH-Signature-Schemes

A Python framework for analyzing seed recovery in post-quantum cryptographic (PQC) signature schemes based on the MPCitH (Multi-Party Computation in the Head) paradigm. This project implements deterministic key generation from user-controlled seeds and includes an oracle algorithm to test whether candidate seeds produce valid key pairs.

**Purpose:** Test the security of MPCitH-based signature schemes against seed recovery attacks by simulating Code-Based Analysis (CBA) bit-flip attacks. This is a research tool for security analysis of PQC implementations ahead of standardization.

> **Disclaimer:** We do not promote unethical attacks or seed recovery via unauthorized means. This framework is strictly for controlled security evaluation in research and development environments.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Setup & Installation](#setup--installation)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Set Up Local SDitH Library](#2-set-up-local-sdith-library)
  - [3. Build the Bridge](#3-build-the-bridge)
  - [4. Run the Framework](#4-run-the-framework)
- [Architecture & Folder Structure](#architecture--folder-structure)
- [Usage](#usage)
- [Implemented Features](#implemented-features)
- [License & Attribution](#license--attribution)
- [Troubleshooting](#troubleshooting)

---

## Features

- **Deterministic Key Generation:** Generate SDitH key pairs from arbitrary bit seeds without internal randomness.
- **Multi-Level Support:** Support for NIST security levels L1 (128-bit), L3 (192-bit), and L5 (256-bit).
- **Oracle Algorithm:** Verify candidate seeds against known public keys to test seed recovery feasibility.
- **Noise Injection:** Introduce controlled bit-flip noise to seeds (CBA simulation).
- **Vendor-Friendly:** All required cryptographic code is vendored locally—no external absolute paths required.
- **GitHub-Ready:** Fully self-contained repository structure suitable for version control and distribution.

---

## Requirements

### System

- **macOS** (Darwin), **Linux**, or **Windows** with WSL2
- **CMake** 3.10+
- **GCC/Clang** C compiler with C99 support
- **Python** 3.7+ (for the framework CLI)
- **Bash** shell (for setup and build scripts)

### Build Dependencies

```bash
# macOS (using Homebrew)
brew install cmake gcc

# Ubuntu/Debian
sudo apt-get install cmake build-essential

# Fedora
sudo dnf install cmake gcc
```

---

## Setup & Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd Seed-Recovery-Framework-for-MPCitH-Signature-Schemes
```

### 2. Set Up Local SDitH Library

The framework requires the SDitH reference implementation source code to build the C bridge locally. You must first point the setup script to your external copy of the SDitH-v2 reference implementation.

#### Option A: Using Relative Path (Default)

If you have `SDitH-v2` installed one level above your repository:

```bash
bash setup_sdith_local.sh -v cat1_fast
```

#### Option B: Using Absolute Path

If your SDitH-v2 reference is elsewhere:

```bash
bash setup_sdith_local.sh \
  -p /absolute/path/to/SDitH-v2/Reference_Implementation \
  -v cat1_fast
```

#### Option C: Vendor Multiple Variants

To include all security levels you may choose one by one which to use from the 6 available (CAT1_FAST, CAT3_FAST, CAT5_FAST, CAT1_SHORT, CAT3_SHORT, CAT5_SHORT):

```bash
bash setup_sdith_local.sh -v cat1_fast
bash setup_sdith_local.sh -v cat3_fast
bash setup_sdith_local.sh -v cat5_fast
```

**What this does:**

- Creates local `SDitH-Library/sdith_cat{1,3,5}_{fast,short}/` folders
- Copies all required source files (src/, lib/aes/, lib/sha3/) from the external reference
- Generates a local `CMakeLists.txt` configured for in-repo building
- Creates variant-specific build scripts

### 3. Build the Bridge

After setup, compile the C bridge for your chosen variant:

```bash
bash build_sdith_[variant].sh
```

**Build output:**

- **macOS:** `SDitH-Library/sdith_cat1_fast/build/libsdith_keygen.dylib`
- **Linux:** `SDitH-Library/sdith_cat1_fast/build/libsdith_keygen.so`
- **Windows:** `SDitH-Library/sdith_cat1_fast/build/libsdith_keygen.dll`
- **Python Interface:** Automatically detects and loads the built library via ctypes

### 4. Run the Framework

```bash
python3 oracle_algorithm.py
```

You will be presented with an interactive menu to select:

1. Cryptographic model (currently SDitH; others in progress)
2. Security level (L1, L3, L5)
3. Operation (generate keys, inject noise, test candidates)

---

## Architecture & Folder Structure

```text
.
├── README.md                          # This file
├── oracle_algorithm.py                # Main Python framework and CLI
├── setup_sdith_local.sh               # Setup script (with -p, -v flags)
├── build_sdith_*.sh                   # Build scripts per variant
├── SDitH-Library/
│   ├── sdith_cat1_fast/               # Vendored CAT1 variant
│   │   ├── src/                       # Core SDitH implementation (29 files)
│   │   ├── lib/
│   │   │   ├── aes/                   # AES/Rijndael cryptography
│   │   │   └── sha3/                  # Keccak/SHA-3 hashing
│   │   ├── wrapper/
│   │   │   ├── sdith_keygen_bridge.c  # Keygen-only C bridge
│   │   │   └── sdith_keygen_bridge.h  # Bridge header
│   │   ├── CMakeLists.txt             # Local build config
│   │   └── build/                     # Compiled artifacts (generated)
│   │       └── libsdith_keygen.{dylib,so}
│   ├── sdith_cat3_fast/               # (Optional) CAT3 variant
│   └── sdith_cat5_fast/               # (Optional) CAT5 variant
├── SDITH_LICENSE.txt                  # SDitH Apache-2.0 License copy
└── [other model implementations TBD]
```

---

## Usage

Run the framework without arguments to enter interactive mode:

```bash
python3 oracle_algorithm.py
```

**Menu Flow:**

```text
Welcome to the Seed Recovery Framework for MPCitH Signature Schemes!

Available models:
    1: SDITH
    (Working on... MIRATH, MQOM, PERK, RYDE)
Select the model to test (0 to exit): 1

Selected model: SDITH

Select the operation:
    0: Exit the program
    1: Generate random seed and keys
    2: Introduce noise to a candidate seed with CBA bit-flip probability values
    3: Test a singular candidate seed
Enter the operation: 1

Select the security level (L1, L3, L5)
Enter the security level (write 1, 3, or 5): 1

Generated seeds and keys for SDITH 1:
skseed: 287496...(128-bit integer)...
pkseed: 125739...(128-bit integer)...
public_key: a1f3b5....(hex-encoded public key bytes)....
private_key: 8f2c9d....(hex-encoded secret key bytes)....
```

**Output Files (created in working directory):**

- `SDITH_L1_skseed.pem` — Secret key seed (decimal integer)
- `SDITH_L1_pkseed.pem` — Public key seed (decimal integer)
- `SDITH_L1_public_key.pem` — Public key (hex-encoded bytes)
- `SDITH_L1_private_key.pem` — Secret key (hex-encoded bytes)

---

## Implemented Features

### ✅ Completed

### SDitH Model

- [x] Deterministic key generation from arbitrary pkseed + skseed
- [x] Support for L1 (CAT1_FAST), L3 (CAT3_FAST), L5 (CAT5_FAST)
- [x] Oracle algorithm for seed candidacy testing
- [x] Binary-safe key serialization (hex format)
- [x] Programmatic API + interactive CLI

#### Noise Injection

- [x] Random bit-flip function with controllable alpha, beta probabilities
- [x] Integration with CBA attack simulation

#### Framework Infrastructure

- [x] Local C bridge (sdith_keygen_bridge.c)
- [x] CMake build system (in-repo, no external paths)
- [x] Automated setup/build scripts with variant selection

### 🚧 In Progress

- [ ] MIRATH model implementation
- [ ] MQOM model implementation
- [ ] PERK model implementation
- [ ] RYDE model implementation
- [ ] Option 3: Test candidate seed against oracle
- [ ] Option 4: BBLM attack implementation

### 📋 Future Work

- [ ] Batch seed testing (parallel oracle checks)
- [ ] Statistical analysis tools for recovery feasibility
- [ ] Graphical UI for key generation workflow
- [ ] Support for hardened parameter sets

---

## License & Attribution

### SDitH Reference Implementation

This framework **includes vendored source code** from the **SDitH-v2 reference implementation**, which is distributed under the **Apache License 2.0**.

**SDitH License Notice:**

```text
The SDitH implementation (src/, lib/aes/, lib/sha3/) is provided by the
cryptographic research community and is distributed under the Apache License 2.0.

You are free to:
  - Use, modify, and distribute this code
  - Include it in proprietary projects (with proper attribution)

You must:
  - Include a copy of the Apache 2.0 license in distributions
  - Provide attribution to the original SDitH authors
  - Document any modifications you make

See SDITH_LICENSE.txt for the full Apache 2.0 license text.
```

**Full SDitH Reference:**

- **Project:** <https://github.com/kuccak/SDitH>
- **License:** Apache License 2.0
- **Upstream Commit:** [Refer to your vendored version's git history]

### Framework License

The framework code in `oracle_algorithm.py`, `setup_sdith_local.sh`, and `sdith_keygen_bridge.c` (wrapper only) are distributed under [**specify your license here**, e.g., MIT, GPL-3.0, or match SDitH's Apache 2.0].

---

## Troubleshooting

### Build Issues

#### Error: "External SDitH reference not found"

```bash
# Make sure the path to SDitH-v2 is correct
bash setup_sdith_local.sh --help          # See usage
bash setup_sdith_local.sh -p /correct/path/to/SDitH-v2/Reference_Implementation
```

#### Error: "SDitH bridge library not found"

```bash
# Build was skipped. Run the build script.
bash build_sdith_cat1_fast.sh
```

#### CMake configuration error (missing dependencies)

```bash
# Ensure CMake and compiler are installed
cmake --version
gcc --version

# On macOS, ensure Xcode command line tools are installed
xcode-select --install
```

### Runtime Issues

#### Error: "cannot open source file" in C bridge

- Ensure `setup_sdith_local.sh` completed successfully: check `SDitH-Library/` folder exists
- Verify copy operations: `ls SDitH-Library/sdith_cat1_fast/src/sdith_signature.h`

#### Python: "FileNotFoundError: ... libsdith_bridge ..."

- Build the library: `bash build_sdith_cat1_fast.sh`
- Verify output: `ls SDitH-Library/sdith_cat1_fast/build/libsdith_keygen.*`

#### Segmentation fault during keygen

- Check that seed integers fit in lambda_bytes: L1 → 128 bits max, L3 → 192 bits max, L5 → 256 bits max
- Regenerate with `python3 -c "print((1 << 128) - 1)"` to find max value

---

## Contributing & Reporting Issues

If you encounter bugs or have suggestions:

1. **Check existing issues** on the project repository
2. **Document the problem:**
   - OS and Python version (`python3 --version`)
   - Exact command run and full error output
   - Steps to reproduce
3. **Create an issue** with the above details

---

## Citation

If you use this framework in academic research, please cite as:

```bibtex
@software{seed_recovery_mpcith_2026,
  author = {[Juan Esteban Vásquez / Universidad de los Andes]},
  title = {Seed-Recovery-Framework-for-MPCitH-Signature-Schemes},
  year = {2026},
  note = {Available at: \url{https://github.com/JuanesVpcb/Seed-Recovery-Framework-for-MPCitH-Signature-Schemes}}
}
```

Also acknowledge the SDitH reference implementation (see License section above).

---

## Contact & Support

For questions about:

- **Framework Usage:** Create an issue / Contact info: <je.vasquez2@uniandes.edu.co>
- **SDitH Algorithm:** Refer to <https://github.com/kuccak/SDitH>
- **PQC Standardization:** See NIST Post-Quantum Cryptography Project

---

**Last Updated:** March 2026  
**Maintained By:** Juan Esteban Vásquez Parra
**Status:** Active Development (SDitH complete, other models in progress)
