# Seed Recovery Framework for MPCitH Signature Schemes

Research framework for controlled seed-recovery experiments against MPC-in-the-Head signature schemes.

## What Is Currently Implemented

- CLI workflow in `seed_recovery_framework.py`.
- Supported models in `Schemes/`:
  - SDitH
  - PERK
  - RYDE
  - Mirath
  - MQOM
- Supported security levels: `1`, `3`, `5`.
- Noise generation and candidate recovery pipeline.
- BBLM-based candidate ranking via local `BBLMAlgorithms/` modules.
- Plotting of recovery results by beta:
  - combined figure with all levels
  - one figure per security level

## Repository Layout

```text
.
├── seed_recovery_framework.py
├── helper_algorithms.py
├── abstract_oracle.py
├── Schemes/
│   ├── sdith_algorithms.py
│   ├── perk_algorithms.py
│   ├── ryde_algorithms.py
│   ├── mirath_algorithms.py
│   └── mqom_algorithms.py
├── BBLMAlgorithms/
│   ├── MonteCarlo.py
│   ├── okeanode.py
│   ├── candidate.py
│   ├── extended_candidate.py
│   └── enumeration_utils.py
└── files/
    ├── keys/
    ├── noisy_seeds/
    ├── bblm/
    └── figures/
```

## Usage

Run:

```bash
python3 seed_recovery_framework.py
```

Menu options:

1. Generate seeds and keys
2. Generate noisy seeds
3. Run BBLM recovery
4. Plot BBLM recovery results
5. Test a single candidate seed

## Plot Outputs

Option 4 generates line plots with per-beta recovery percentages, aggregated across all available model result files for each method.

Generated files:

- `files/figures/bblm_results_all_levels_by_beta.png`
- `files/figures/bblm_results_L1_by_beta.png`
- `files/figures/bblm_results_L3_by_beta.png`
- `files/figures/bblm_results_L5_by_beta.png`

## Dependencies

- Python 3.10+
- `bitarray`
- `matplotlib`

MQOM adapter note:

- `Schemes/mqom_algorithms.py` imports the Python reference implementation from a sibling directory:
  - `../MQOM-v2/Reference_Implementation_Python`

## Model License Status

License information was checked from online resources linked by NIST Round-2 Additional Signatures:

- NIST page: <https://csrc.nist.gov/projects/pqc-dig-sig/round-2-additional-signatures>
- Scheme resource pages and official package downloads were inspected for `LICENSE`/`COPYING` entries.

| Model | Used in this repo via | Online source checked | License status (verified) |
| --- | --- | --- | --- |
| SDitH | `Schemes/sdith_algorithms.py` | <https://sdith.org/resources.html> (package: `sdith-package-v2.zip`), <https://github.com/sdith/sdith> (LICENSE.txt) | `LICENSE`: Distributed under Apache 2.0 License. |
| PERK | `Schemes/perk_algorithms.py` | <https://pqc-perk.org/resources.html> (package: `perk-v2.2.0.zip`) | `LICENSE` files are present. Sample text states: "This software is released into the public domain." |
| RYDE | `Schemes/ryde_algorithms.py` | <https://pqc-ryde.org/resources.html> (package: `ryde_v2.1.0.zip`) | `LICENSE` files are present and contain Apache License 2.0 text. |
| Mirath | `Schemes/mirath_algorithms.py` | <https://pqc-mirath.org/resources.html> (package: `mirath_v2.1.0.zip`) | No explicit `LICENSE`/`COPYING` file found in the inspected package. |
| MQOM | `Schemes/mqom_algorithms.py` + `../MQOM-v2/Reference_Implementation_Python` | <https://mqom.org/resources.html> (package: `mqom-v2.1.zip`), <https://github.com/mqom/mqom-v2> (LICENSE.txt) | `LICENSE`: Distributed under MIT License. |

Important:

- For Mirath, no standalone license file was found in the inspected online packages. Before redistribution, confirm licensing directly with the maintainers or official repositories and vendor the license text in this repository.
- For MQOM, PERK, RYDE, and SDitH, treat the package-embedded / GitHub repository `LICENSE` files as the authoritative source for the exact code version you use.

## Disclaimer

For authorized research and evaluation only. Do not use this framework against systems or data without explicit permission.
