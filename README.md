# Seed Recovery Framework for MPCitH Signature Schemes

This repository is a research framework for seed-recovery experiments against MPC-in-the-Head signature schemes. It combines:

- scheme-specific oracle/keygen bridges and wrappers,
- a noisy-seed generation workflow,
- a budget-aware BBLM recovery pipeline,
- and plotting/reporting utilities.

The code is intended for controlled academic/security evaluation.

## Current Status

- Models wired in CLI: SDitH, Mirath, MQOM, PERK, RYDE
- Security levels: 1, 3, 5
- BBLM path: budget-aware profiles using time and memory constraints
- Parallel execution: multiprocessing over noisy seeds during recovery
- BBLM core connection: uses modules from BBLM-Algorithms (OKEA/candidate enumeration stack)

## Repository Layout

```text
.
├── seed_recovery_framework.py      # Main CLI (options 1..5)
├── helper_algorithms.py            # Noise + connectors to BBLM-Algorithms
├── abstract_oracle.py              # Oracle interface contract
├── Schemes/                        # Scheme-specific oracle implementations
│   ├── sdith_algorithms.py
│   ├── perk_algorithms.py
│   ├── ryde_algorithms.py
│   ├── mqom_algorithms.py
│   └── mirath_algorithms.py
├── SchemeBridges/
│   └── sdith_library_bridge.py     # ctypes bridge for SDitH library wrapper
├── SDitH-Library/
│   └── wrapper/
│       ├── sdith_keygen_bridge.c
│       └── sdith_keygen_bridge.h
├── BBLMAlgorithms/                 # Original BBLM algorithm modules used by connector
│   ├── candidate.py
│   ├── extended_candidate.py
│   ├── enumeration_utils.py
│   ├── basic_enumerator.py
│   ├── okeanode.py
│   └── ...
├── files/                          # Generated keys/noisy seeds/results/plots
└── setup_sdith_local.sh            # SDitH local setup helper
```

## Usage

Run:

```bash
python3 seed_recovery_framework.py
```

Menu flow:

1. Select model
2. Select security level (1, 3, or 5)
3. Select operation:
   - 1: generate seeds/keys
   - 2: generate noisy seeds
   - 3: run BBLM recovery (budget-aware)
   - 4: plot BBLM results
   - 5: test a single candidate seed

## BBLM Recovery Profiles

The recovery run evaluates two adversary profiles:

- Average adversary: Btime = 2^30, Bmemory = 2^30
- Strong adversary: Btime = 2^50, Bmemory = 2^50

The candidate exploration bound is derived from these budgets (instead of a fixed max-candidates input), and results are saved per profile in:

- files/bblm/<`MODEL`>_L<`LEVEL`>_recovery.json

Each run prints a compact per-profile summary table with total seeds, recoveries, average success probability, and best per-beta probability.

## Notes on Dependencies

- Python 3.10+ recommended.
- The BBLM-Algorithms modules use bitarray.
- SDitH bridge compilation depends on your local toolchain (C compiler/CMake) when rebuilding wrappers.

## Acknowledgements

This framework builds on the work of multiple research groups and submission teams.

### BBLM Recovery Algorithms

- Integrated from the BBLM algorithm codebase included in this repository under BBLM-Algorithms.
- Credit to the authors and contributors of the original BBLM recovery framework and related thesis/paper artifacts.

### Signature Scheme Implementations and Submissions

- SDitH: based on the SDitH submission/reference materials included in this project structure.
- PERK submitters (from submission README): Najwa Aaraj, Slim Bettaieb, Loic Bidoux, Alessandro Budroni, Victor Dyseryn, Andre Esser, Thibauld Feneuil, Philippe Gaborit, Mukul Kulkarni, Victor Mateu, Marco Palumbi, Lucas Perin, Matthieu Rivain, Jean-Pierre Tillich, Keita Xagawa.
- RYDE submitters (from submission README): Nicolas Aragon, Magali Bardet, Loic Bidoux, Jesus-Javier Chi-Dominguez, Victor Dyseryn, Thibauld Feneuil, Philippe Gaborit, Antoine Joux, Romaric Neveu, Matthieu Rivain, Jean-Pierre Tillich, Adrien Vincotte.
- Mirath submitters (from submission README): Gora Adj, Nicolas Aragon, Stefano Barbero, Magali Bardet, Emanuele Bellini, Loic Bidoux, Jesus-Javier Chi-Dominguez, Victor Dyseryn, Andre Esser, Thibauld Feneuil, Philippe Gaborit, Romaric Neveu, Matthieu Rivain, Luis Rivera-Zamarripa, Carlo Sanna, Jean-Pierre Tillich, Javier Verbel, Floyd Zweydinger.
- MQOM2: based on the MQOM2 submission package (including Reference_Implementation_Python) included in the project environment.

Please refer to each scheme's original package documentation, cover sheets, and license files for definitive authorship, ownership, and licensing terms.

## Disclaimer

This code is for authorized testing and research only. Do not use it against systems or data without explicit permission.

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
