import os
import json
import math
from time import time_ns

from bitarray import bitarray

from abstract_oracle import MPCitHOracle
from Schemes.sdith_algorithms import SDitHOracle
from Schemes.perk_algorithms import PERKOracle
from Schemes.ryde_algorithms import RYDEOracle
from Schemes.mqom_algorithms import MQOMOracle
from Schemes.mirath_algorithms import MirathOracle
from helper_algorithms import introduce_noise, extract_seedpk_and_y, load_noisy_seeds_from_file, ranked_seed_candidates_from_noisy
from BBLMAlgorithms.MonteCarlo import (
    build_posteriors_from_tilde,
    create,
    findOptimalB2,
    generate_candidates_trimmed,
    getMaximumWeight,
    getMinimumWeight,
)

# Define constants for the different models
SDITH = 1
MIRATH = 2
MQOM = 3
PERK = 4
RYDE = 5

# Static default profiles derived from Paper-Recovery-Seeds results.
# Keyed by seed length W (bits) and beta.
DEFAULT_BETAS = [0.03, 0.05, 0.10, 0.15, 0.20, 0.25]
DEFAULT_B2_PROFILES = {
    128: {
        0.03: {"B2": 160480, "w": 4, "mu": 64, "eta": 2},
        0.05: {"B2": 156017, "w": 4, "mu": 64, "eta": 2},
        0.10: {"B2": 259095, "w": 16, "mu": 16, "eta": 2},
        0.15: {"B2": 189709, "w": 4, "mu": 32, "eta": 2},
        0.20: {"B2": 218178, "w": 4, "mu": 32, "eta": 2},
        0.25: {"B2": 264118, "w": 8, "mu": 64, "eta": 2},
    },
    192: {
        0.03: {"B2": 136560, "w": 4, "mu": 64, "eta": 2},
        0.05: {"B2": 141080, "w": 4, "mu": 64, "eta": 2},
        0.10: {"B2": 175837, "w": 4, "mu": 64, "eta": 2},
        0.15: {"B2": 218667, "w": 4, "mu": 64, "eta": 2},
        0.20: {"B2": 284221, "w": 8, "mu": 64, "eta": 2},
        0.25: {"B2": 348805, "w": 16, "mu": 64, "eta": 2},
    },
    256: {
        0.03: {"B2": 144932, "w": 4, "mu": 64, "eta": 2},
        0.05: {"B2": 154656, "w": 4, "mu": 64, "eta": 2},
        0.10: {"B2": 174752, "w": 4, "mu": 64, "eta": 2},
        0.15: {"B2": 282769, "w": 4, "mu": 64, "eta": 4},
        0.20: {"B2": 326935, "w": 8, "mu": 64, "eta": 2},
        0.25: {"B2": 430113, "w": 16, "mu": 64, "eta": 4},
    },
}

# ============================== Core BBLM-style Seed Recovery Functions (Option 3) ==============================
def _effective_profile_length_bits(model_name: str, oracle: MPCitHOracle) -> int:
    """Resolve the profile W used for default parameters.

    For MQOM, use non-MQOM profile levels:
    - L1, L3, L5 -> L5 profile (256)
    """
    if model_name == "MQOM":
        return 256

    seed_bits = oracle.params["lambda_bytes"] * 8
    return min((128, 192, 256), key=lambda w: abs(w - seed_bits))

def _get_default_b2_profile(
    model_name: str,
    oracle: MPCitHOracle,
    beta: float,
) -> tuple[dict, str]:
    """Get the default B2* profile for the given model, oracle, and beta, based on static profiles
    derived from Paper-Recovery-Seeds results."""
    W = _effective_profile_length_bits(model_name, oracle)
    W_key = min((128, 192, 256), key=lambda w: abs(w - W))
    beta_key = min(DEFAULT_BETAS, key=lambda b: (abs(b - beta), b))

    profile = DEFAULT_B2_PROFILES[W_key][beta_key].copy()
    source = f"static_default:W{W_key}_beta{beta_key:.2f}"
    if abs(beta_key - beta) > 1e-12:
        source += f"_from_beta{beta:.2f}"
    return profile, source

def _process_noisy_seed(
    noisy_seed: bytes,
    alpha: float,
    beta: float,
    w: int,
    mu: int,
    eta: int,
    candidate_limit: int,
    candidate_mode: str,
    oracle: MPCitHOracle,
    seedpk: bytes,
    y: bytes,
) -> bool:
    """Process a single noisy seed to recover the original; returns if seed was recovered."""
    try:
        candidate_seeds = ranked_seed_candidates_from_noisy(
            noisy_seed,
            alpha=alpha,
            beta=beta,
            w=w,
            mu=mu,
            eta=eta,
            max_candidates=candidate_limit,
            mode=candidate_mode,
        )
    except (OverflowError, MemoryError, ValueError):
        return False
    for candidate_seed in candidate_seeds:
        derived_pk, _ = oracle.keygen_from_seeds(candidate_seed, seedpk)
        if oracle.get_y(derived_pk) == y: return True
    return False

def _parse_bblm_custom_input(raw: str) -> tuple[float, int, int, int, list[float]]:
    """Parse custom BBLM params from 'alpha;w;mu;eta;beta1,beta2,...' format."""
    parts = [p.strip() for p in raw.split(";")]
    if len(parts) != 5:
        raise ValueError("Expected format: alpha;w;mu;eta;beta1,beta2,...")

    alpha = float(parts[0])
    w = int(parts[1])
    mu = int(parts[2])
    eta = int(parts[3])
    betas = [float(v.strip()) for v in parts[4].split(",") if v.strip()]

    if not (0 <= alpha <= 1):
        raise ValueError("alpha must be in [0,1]")
    if w <= 0 or mu <= 0:
        raise ValueError("w and mu must be positive")
    if eta <= 0:
        raise ValueError("eta must be positive")
    if not betas:
        raise ValueError("at least one beta is required")
    for beta in betas:
        if not (0 <= beta <= 1):
            raise ValueError("all beta values must be in [0,1]")

    return alpha, w, mu, eta, betas

def _budget_candidate_limit_from_model_prediction(
    noisy_seed: bytes,
    alpha: float,
    beta: float,
    w: int,
    mu: int,
    eta: int = 1,
    scale: int = 10000,
    fixed_B2: int | None = None,
    max_candidates: int | None = None,
) -> int:
    """Derive a candidate budget from Model_Prediction.py using Btime/Bmemory.
    
    If fixed_B2 is provided, use it instead of optimizing B2* for each seed (faster, more stable)."""
    s_tilde = bitarray()
    s_tilde.frombytes(noisy_seed)
    s_tilde = s_tilde[: len(noisy_seed) * 8]
    W = len(s_tilde)

    if W == 0 or W % w != 0 or eta <= 0:
        return 1

    posterior = build_posteriors_from_tilde(s_tilde, alpha, beta)
    blocks = generate_candidates_trimmed(posterior, W, w, eta, mu, scale=scale)
    if not blocks:
        return 1

    Bmin = int(getMinimumWeight(blocks, scale))
    Bmax = int(getMaximumWeight(blocks, scale))
    if Bmax <= Bmin:
        return 1

    if fixed_B2 is None:
        B2 = findOptimalB2(
            blocks,
            Bmin,
            Bmax,
            W,
            w,
            eta,
            mu,
            2<<29,
            2<<29,
            2<<4,
            2<<3,
            2<<5,
            scale,
        )
        if B2 is None or B2 <= Bmin:
            return 1
    else:
        B2 = int(fixed_B2)

    # Keep B2 in the admissible range for matrix construction.
    B2 = max(Bmin + 1, min(B2, Bmax))
    matrix = create(blocks, Bmin, B2, W, w, eta, mu, scale)
    candidate_limit = max(1, int(matrix[0][0]))
    if max_candidates is not None:
        candidate_limit = min(candidate_limit, max_candidates)
    return candidate_limit


# =================================== User Interface for Testing the Algorithms ====================================
def generate_seeds(model_name: str, oracle: MPCitHOracle) -> None:
    """Generates seeds and keys for the selected model and security level, saves them to files, and returns them as a tuple.
    
    Params:
        model_name: The name of the selected model (e.g., "SDITH").
        oracle: The instantiated oracle for the selected model and security level.
    """
    
    skseed, pkseed = oracle.seeds()  # Generate seeds and keys using the oracle for the selected model and security level
    expanded_material = oracle.expand((skseed, pkseed))  # Expand the seeds according to the oracle's expand method
    y = oracle.proof(expanded_material)  # Generate the proof using the oracle's proof method
    pk = oracle.verify((skseed, pkseed), y, expanded_material)  # Verify the proof using the oracle's verify method
    if pk == b"":
        print("Verification failed. The generated proof did not match the expected value.")
        return
    
    pk, sk = oracle.keygen_from_seeds(skseed, pkseed)  # Generate the pk and sk from the seeds using the oracle's keygen_from_seeds
    security_level = oracle.security_level # Get the security level from the oracle for file naming and display purposes
    
    # Save keys and seeds to unencrypted files (testing the algorithm, thus no encryption needed)
    os.makedirs("files/keys", exist_ok=True)
    with open(f"files/keys/{model_name}_L{security_level}_skseed.pem", "w") as skseed_file:
        skseed_file.write(skseed.hex())
    if model_name != "MQOM":
        with open(f"files/keys/{model_name}_L{security_level}_pkseed.pem", "w") as pkseed_file:
            pkseed_file.write(pkseed.hex())
    with open(f"files/keys/{model_name}_L{security_level}_pk.pem", "w") as public_key_file:
        public_key_file.write(pk.hex())
    with open(f"files/keys/{model_name}_L{security_level}_sk.pem", "w") as private_key_file:
        private_key_file.write(sk.hex())
    
    print(f"\nGenerated seeds and keys for {model_name} {security_level}:")
    print(f"skseed: {(skseed.hex())}")
    if model_name != "MQOM": print(f"pkseed: {pkseed.hex()}")
    print(f"public_key: {pk.hex()}")
    print(f"private_key: {sk.hex()}")

def introduce_noise_to(model_name: str, oracle: MPCitHOracle) -> None:
    """Introduces noise to a candidate seed using CBA bit-flip probabilities and saves the noisy seeds to a file.
    You may select multiple beta values to generate different sets of noisy seeds for the same candidate seed and alpha value.
    
    Params:
        model_name: The name of the selected model (e.g., "SDITH").
        oracle: The instantiated oracle for the selected model and security level.
    """
    
    # Get the alpha, beta and sample count values for CBA noise generation.
    alpha = 0.001 # float(input("Enter the alpha (0 -> 1) value to use between 0 and 1 (default: 0.001): ") or 0.001)
    #while True:
    #    if (0 <= alpha <= 1): break
    #    print("Invalid beta or alpha value. Please enter a value between 0 and 1.")
        
    while True:
        beta_values = input("Enter the beta (1 -> 0) values to use between 0 and 1 (default: 0.03, 0.05, 0.10, 0.15, 0.20, 0.25): ")
        betas = []
        if beta_values.strip() == "":
            betas = DEFAULT_BETAS
            break
        for beta_str in beta_values.split(","):
            try:
                beta_val = float(beta_str.strip())
                if beta_val < 0 or beta_val > 1:
                    print(f"beta value {beta_val} is out of range [0,1]. Skipping this value.")
                    continue
                betas.append(beta_val)
            except ValueError:
                print(f"Invalid beta value '{beta_str}'. Please enter numeric values. Skipping this value.")
                continue
        if betas == []: print("No valid beta values entered. Please try again.")
        else: break
    
    sample_count = int(input("How many noisy seeds to generate with these parameters? (default: 10): ") or 10)
    while True:
        if sample_count > 0: break
        print("The number of noisy seeds must be a positive integer. Please try again.")
        sample_count = int(input("How many noisy seeds to generate with these parameters? (default: 10): ") or 10)

    # Open the file containing the candidate seed to introduce noise to, with validation and default
    candidate_seed_f = input("\nEnter the name of the file with the seed to introduce noise to (blank for default): ")
    if candidate_seed_f == "":
        candidate_seed_f = f"files/keys/{model_name}_L{oracle.security_level}_skseed.pem"  # Default file name for testing
    try:
        with open(candidate_seed_f, "r") as seed_file:
            seed = bytes.fromhex(seed_file.read().strip())
    except FileNotFoundError:
        print(f"File {candidate_seed_f} not found. Please check the file name and try again.")
        return
    except ValueError:
        print(f"File {candidate_seed_f} does not contain a valid bytes-coded seed. Please check the file contents and try again.")
        return

    if len(seed) == 0:
        print("The selected seed is empty. Generate keys first (option 1) or provide a valid seed file.")
        return
    
    # Save noisy seeds in one aggregate file per (model, level, alpha, beta): one seed per line.
    os.makedirs("files/noisy_seeds", exist_ok=True)

    for beta in betas:
        noisy_file = f"files/noisy_seeds/{model_name}_L{oracle.security_level}_{alpha:.3f}_{beta:.2f}.pem"
        with open(noisy_file, "w") as noisy_seed_file:
            for _ in range(sample_count):
                noisy_seed = introduce_noise(seed, alpha, beta)
                noisy_seed_file.write(noisy_seed.hex() + "\n")
    
def run_bblm_on(model_name: str, oracle: MPCitHOracle) -> None:
    """Runs the BBLM attack for the selected model and security level, saving the results to a json file.
    
    Params:
        model_name: The name of the selected model (e.g., "SDITH").
        oracle: The instantiated oracle for the selected model and security level.
    """
    
    # TODO: Fix MQOM results and profiles, currently not working as expected (recovery rates too low even for low noise levels, 
    # likely due to incorrect parameter selection or implementation details).
    if model_name == "MQOM": 
        print("MQOM is currently not working as expected. To be fixed in future iterations.")
        return
    
    # Keep parameter selection compact: one defaults question plus one optional custom line.
    use_defaults = (input("\nUse defaults? (y/n): ").strip().lower() or "y")
    if use_defaults in ("y", "yes"):
        alpha = 0.001
        beta_values = DEFAULT_BETAS
    else:
        try:
            raw = input("Enter alpha;w;mu;eta;beta1,beta2,... : ").strip()
            alpha, w, mu, eta, beta_values = _parse_bblm_custom_input(raw)
        except ValueError as exc:
            print(f"Invalid custom BBLM parameters: {exc}")
            return
    
    b2_mode = input("B2* strategy [d=default, m=manual, o=optimize per seed] (default: d): ").strip().lower() or "d"
    if b2_mode not in ("d", "m", "o"):
        print("Invalid B2* strategy. Use d, m, or o.")
        return

    manual_b2_star = None
    if b2_mode == "m":
        try:
            manual_b2_star = int(input("Enter manual B2* (>0): ").strip())
            if manual_b2_star <= 0:
                raise ValueError
        except ValueError:
            print("Invalid manual B2*. It must be a positive integer.")
            return

    candidate_policy = input("Candidate ranking policy [o=okea, l=lightweight, b=beam] (default: b): ").strip().lower() or "b"
    if candidate_policy not in ("o", "l", "b"):
        print("Invalid candidate policy. Use o, l, or b.")
        return

    if candidate_policy == "o":
        max_candidates_cap = 2 << 9
        if oracle.security_level == 5: max_candidates_cap = 2 << 8
        candidate_mode = "okea"
    elif candidate_policy == "l":
        max_candidates_cap = 2 << 20
        if oracle.security_level == 5: max_candidates_cap = 2 << 19
        candidate_mode = "lightweight"
    else:
        max_candidates_cap = 2 << 10
        if oracle.security_level == 5: max_candidates_cap = 2 << 9
        candidate_mode = "beam"
    
    print(f"\nRunning BBLM-style reconstruction for {model_name} L{oracle.security_level}...")
    print(f"   alpha={alpha}, betas={beta_values}")
    print(f"   B2* strategy: {b2_mode} (manual B2*={manual_b2_star if manual_b2_star is not None else 'N/A'})")
    print(f"   candidate_mode={candidate_mode}, max_candidates_cap={max_candidates_cap}")

    # Read the public key from the file for the selected model and security level, with validation
    pk_file = f"files/keys/{model_name}_L{oracle.security_level}_pk.pem"
    try:
        with open(pk_file, "r") as f:
            public_key = bytes.fromhex(f.read().strip())
    except Exception as exc:
        print(f"Could not read public key file: {exc}. Run option 1 to generate keys first and try again.")
        return
    
    results = {
        "model": model_name,
        "security_level": oracle.security_level,
        "alpha": alpha,
        "b2_strategy": b2_mode,
        "candidate_mode": candidate_mode,
        "max_candidates_cap": max_candidates_cap,
        "cost_model": {
            "Cbase": 2<<4,
            "Cblock": 2<<3,
            "Coracle": 2<<5,
        },
    }

    beta_results = []
    for beta in beta_values:
        print(f"\nTesting beta={beta:.2f}...")
        noisy_file = f"files/noisy_seeds/{model_name}_L{oracle.security_level}_{alpha:.3f}_{beta:.2f}.pem"
        noisy_seeds = []
        try:
            noisy_seeds = load_noisy_seeds_from_file(noisy_file, oracle.params["lambda_bytes"])
        except Exception as exc:
            print(f"Could not read noisy seed file {noisy_file}: {exc}")
            continue

        per_seed_results = {}
        per_seed_candidate_limits = []
        recoveries = 0

        # Extract seedpk and y once from the oracle
        seedpk, y = extract_seedpk_and_y(oracle, public_key)

        # Select B2* once per (beta, profile), then compute candidate limits per seed.
        b2_star = None
        b2_source = "optimized_per_seed"

        if b2_mode == "m":
            b2_star = manual_b2_star
            b2_source = "manual"
            w = 4
            mu = 64
            eta = 2
        elif b2_mode == "d":
            rec_profile, b2_source = _get_default_b2_profile(
                model_name,
                oracle,
                beta,
            )
            b2_star = rec_profile["B2"]
            w = rec_profile["w"]
            mu = rec_profile["mu"]
            eta = rec_profile["eta"]

        if b2_star is not None:
            print(
                f"   Using fixed B2*={b2_star} ({b2_source}), "
                f"w={w}, mu={mu}, eta={eta}"
            )
        else:
            print(
                f"   Using per-seed B2* optimization (slow mode), "
                f"w={w}, mu={mu}, eta={eta}"
            )
        print(
            f"   mode={candidate_mode}, cap={max_candidates_cap}"
        )

        candidate_limits_by_seed = {}
        for noisy_seed in noisy_seeds:
            # In safe and manual-limit policies, skip heavy BBLM budget
            # matrix construction and use the configured cap directly.
            t_init = time_ns()
            if candidate_policy == "l" or candidate_policy == "b":
                candidate_limit = max_candidates_cap
            else:
                candidate_limit = _budget_candidate_limit_from_model_prediction(
                    noisy_seed=noisy_seed,
                    alpha=alpha,
                    beta=beta,
                    w=w,
                    mu=mu,
                    eta=eta,
                    fixed_B2=b2_star,
                    max_candidates=max_candidates_cap,
                )
            noisy_hex = noisy_seed.hex()
            candidate_limits_by_seed[noisy_hex] = candidate_limit
            recovered = _process_noisy_seed(
                noisy_seed,
                alpha,
                beta,
                w,
                mu,
                eta,
                candidate_limit,
                candidate_mode,
                oracle,
                seedpk,
                y,
            )
            per_seed_results[noisy_hex] = recovered
            per_seed_candidate_limits.append(candidate_limit)
            if recovered: recoveries += 1
            print(f"      Processed seed ({noisy_hex}). Recovered? {recovered} in {(time_ns() - t_init) / 1e9:.3f}s.")

        seeds_processed = len(noisy_seeds)
        candidate_limit_avg = (sum(per_seed_candidate_limits) / 
                               len(per_seed_candidate_limits)) if per_seed_candidate_limits else 0.0
        beta_results.append({
            "beta": beta,
            "B2_star": b2_star,
            "B2_source": b2_source,
            "w_used": w,
            "mu_used": mu,
            "eta_used": eta,
            "seeds_processed": seeds_processed,
            "recoveries": recoveries,
            "candidate_limit": candidate_limit_avg,
            "per_seed_results": per_seed_results,
        })
        print(f"beta={beta:.2f}: recovered {recoveries}/{seeds_processed} seeds ")

    results["beta_results"] = beta_results
    
    os.makedirs("files/bblm", exist_ok=True)
    with open(f"files/bblm/{model_name}_L{oracle.security_level}_recovery_{candidate_mode}.json", "w") as f:
        json.dump(results, f, indent=2)    

def plot_bblm_results() -> None:
    """Graph BBLM recovery rates per beta, aggregated across all models.

    Creates 3 plots (L1, L3, L5). Each plot contains one line per recovery method
    (currently lightweight and beam), where each point is the recovery percentage
    for a specific beta after compounding all available model result files.
    """

    # Load matplotlib lazily to keep memory lower during attack runs.
    import matplotlib.pyplot as plt

    bblm_dir = "files/bblm"
    if not os.path.exists(bblm_dir):
        print("No BBLM results found. Run option 3 to generate results first and try again.")
        return

    # Structure:
    # aggregated_results[level][method][beta] = {"seeds": int, "recovered": int}
    aggregated_results: dict[int, dict[str, dict[float, dict[str, int]]]] = {}

    for filename in os.listdir(bblm_dir):
        if not filename.endswith(".json"):
            continue

        filepath = os.path.join(bblm_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            print(f"Warning: Could not read {filename}: {exc}")
            continue

        # Prefer metadata from content, then fallback to filename parsing.
        security_level = data.get("security_level")
        method = data.get("candidate_mode")

        if security_level is None or method is None:
            parts = filename.replace(".json", "").split("_")
            parsed_level = None
            parsed_method = None
            for idx, part in enumerate(parts):
                if part.startswith("L") and len(part) > 1 and part[1:].isdigit():
                    parsed_level = int(part[1:])
                if part == "recovery" and idx + 1 < len(parts):
                    parsed_method = parts[idx + 1]
            security_level = security_level if security_level is not None else parsed_level
            method = method if method is not None else parsed_method

        if security_level not in (1, 3, 5) or method is None:
            print(f"Warning: Could not parse security level/method from {filename}")
            continue

        level_bucket = aggregated_results.setdefault(security_level, {})
        method_bucket = level_bucket.setdefault(method, {})

        for beta_result in data.get("beta_results", []):
            beta_val = beta_result.get("beta")
            if beta_val is None:
                continue

            beta = round(float(beta_val), 2)
            beta_bucket = method_bucket.setdefault(beta, {"seeds": 0, "recovered": 0})
            beta_bucket["seeds"] += int(beta_result.get("seeds_processed", 0))
            beta_bucket["recovered"] += int(beta_result.get("recoveries", 0))

    if not aggregated_results:
        print("No valid BBLM results found to plot.")
        return

    fig, axes = plt.subplots(1, 3, figsize=(20, 6), sharey=True)
    method_order = ["lightweight", "beam"]
    method_styles = {
        "lightweight": {"color": "#1f77b4", "marker": "o", "label": "Lightweight"},
        "beam": {"color": "#ff7f0e", "marker": "s", "label": "Beam"},
    }
    plot_series_data: dict[int, dict[str, tuple[list[float], list[float]]]] = {1: {}, 3: {}, 5: {}}

    for idx, security_level in enumerate([1, 3, 5]):
        ax = axes[idx]
        methods_data = aggregated_results.get(security_level, {})

        if not methods_data:
            ax.text(0.5, 0.5, f"No data for L{security_level}", ha="center", va="center", transform=ax.transAxes)
            ax.set_title(f"Security Level {security_level}")
            ax.set_xlabel("Beta")
            ax.grid(True, alpha=0.3)
            continue

        plotted_any_series = False
        for method in method_order:
            if method not in methods_data:
                continue

            beta_buckets = methods_data[method]
            betas = sorted(beta_buckets.keys())
            if not betas:
                continue

            rates = []
            for beta in betas:
                seeds = beta_buckets[beta]["seeds"]
                recovered = beta_buckets[beta]["recovered"]
                rates.append((recovered / seeds) * 100 if seeds > 0 else 0.0)

            style = method_styles.get(method, {"color": "#333333", "marker": "o", "label": method.capitalize()})
            ax.plot(
                betas,
                rates,
                linewidth=2,
                markersize=6,
                color=style["color"],
                marker=style["marker"],
                label=style["label"],
            )
            plot_series_data[security_level][method] = (betas, rates)
            plotted_any_series = True

        ax.set_title(f"Security Level {security_level}", fontsize=12, fontweight="bold")
        ax.set_xlabel("Beta")
        ax.set_ylabel("Recovery Rate (%)")
        ax.set_ylim(0, 105)
        ax.grid(True, alpha=0.3)

        if plotted_any_series:
            ax.legend(loc="best")

    plt.suptitle("BBLM Recovery by Beta (Aggregated Across All Models)", fontsize=14, fontweight="bold", y=1.02)
    plt.tight_layout()

    os.makedirs("files/figures", exist_ok=True)
    out_file = "files/figures/bblm_results_all_levels_by_beta.png"
    plt.savefig(out_file, dpi=150, bbox_inches="tight")
    print(f"Plot saved to {out_file}")

    # Export one figure per security level as well.
    for security_level in [1, 3, 5]:
        level_file = f"files/figures/bblm_results_L{security_level}_by_beta.png"
        fig_level, ax_level = plt.subplots(figsize=(8, 5))

        methods_for_level = plot_series_data.get(security_level, {})
        if not methods_for_level:
            ax_level.text(0.5, 0.5, f"No data for L{security_level}", ha="center", va="center", transform=ax_level.transAxes)
        else:
            for method in method_order:
                if method not in methods_for_level:
                    continue
                betas, rates = methods_for_level[method]
                style = method_styles.get(method, {"color": "#333333", "marker": "o", "label": method.capitalize()})
                ax_level.plot(
                    betas,
                    rates,
                    linewidth=2,
                    markersize=6,
                    color=style["color"],
                    marker=style["marker"],
                    label=style["label"],
                )
            ax_level.legend(loc="best")

        ax_level.set_title(f"Security Level {security_level}", fontsize=12, fontweight="bold")
        ax_level.set_xlabel("Beta")
        ax_level.set_ylabel("Recovery Rate (%)")
        ax_level.set_ylim(0, 105)
        ax_level.grid(True, alpha=0.3)

        fig_level.tight_layout()
        fig_level.savefig(level_file, dpi=150, bbox_inches="tight")
        plt.close(fig_level)
        print(f"Plot saved to {level_file}")

    plt.show()
    
def test_candidate_seed(oracle: MPCitHOracle, candidate_seed: bytes, public_key: bytes) -> bool:
    """Tests a singular candidate seed against the oracle algorithm for the selected model and security level.
    
    Params:
        oracle: The instantiated oracle for the selected model and security level.
        candidate_seed: The candidate seed to test as bytes.
        public_key: The public key to use for the test as bytes.
    Returns:
        A boolean indicating whether the candidate seed passes the test.
    """
    
    seedpk, y = extract_seedpk_and_y(oracle, public_key)
    derived_pk, _ = oracle.keygen_from_seeds(candidate_seed, seedpk)  # Derive the keys from the candidate seed and seedpk
    return (oracle.get_y(derived_pk) == y)  # Return whether the generated proof matches the expected proof


# =================================== Main Function to Run the Console Interface ===================================
def main() -> None:
    # ------------------------------- Model selection -------------------------------
    while True:
        print("\nAvailable models:")
        print("\t1: SDITH")
        print("\t2: MIRATH")
        print("\t3: MQOM (Not working as expected yet, use with caution)")
        print("\t4: PERK")
        print("\t5: RYDE")
        model_input = int(input("Select the model to test: "))
        if model_input not in [SDITH, MIRATH, MQOM, PERK, RYDE]:
            print("Invalid model selected. Please try again.")
            continue
        else:
            model_name = {SDITH: "SDITH", 
                          MIRATH: "MIRATH", 
                          MQOM: "MQOM", 
                          PERK: "PERK", 
                          RYDE: "RYDE"}[model_input]
            print(f"Selected model: {model_name}")
            break
    
    # --------------------------- Security level selection --------------------------
    while True:
        security_level = int(input("\nSelect the security level (1, 3, or 5): "))
        if security_level in [1, 3, 5]: break
        else: print("Invalid security level selected. Please try again.")
    
    # Instantiate the oracle for the selected model and security level
    oracle: MPCitHOracle = None
    try:
        if model_input == SDITH:
            oracle = SDitHOracle(security_level=security_level, fast=True)
        elif model_input == PERK:
            oracle = PERKOracle(security_level=security_level, fast=True)
        elif model_input == RYDE:
            oracle = RYDEOracle(security_level=security_level, fast=True)
        elif model_input == MQOM:
            oracle = MQOMOracle(security_level=security_level)
        elif model_input == MIRATH:
            oracle = MirathOracle(security_level=security_level, fast=True)
        else:
            print("Oracle generation for the selected model is not implemented yet.")
            return
    except Exception as e:
        print(f"Error instantiating oracle for {model_name}: {e}")
        return

    # ----------------------------- Operation selection -----------------------------
    while True:
        print("\nSelect the operation:")
        print("\t0: Exit the program")
        print("\t1: Generate random seed and keys")
        print("\t2: Intrduce noise to a candidate seed with CBA bit-flip probability values")
        print("\t3: Run the BBLM attack")
        print("\t4: Graph results for multiple candidate seeds and noise levels")
        print("\t5: Test a singular candidate seed")
        operation_input = int(input("Enter the operation: "))
        
        # Run through the options
        if operation_input == 0: 
            print("\nExiting the program.")
            return
        elif operation_input == 1: generate_seeds(model_name, oracle)
        elif operation_input == 2: introduce_noise_to(model_name, oracle)
        elif operation_input == 3: run_bblm_on(model_name, oracle)
        elif operation_input == 4: plot_bblm_results()
        elif operation_input == 5:
            candidate_seed_file = input("\nEnter the name of the file with the candidate seed to test (blank for default): ")
            if candidate_seed_file == "":
                candidate_seed_file = f"files/keys/{model_name}_L{oracle.security_level}_skseed.pem"  # Default file name
            try:
                with open(candidate_seed_file, "r") as seed_file:
                    candidate_seed = bytes.fromhex(seed_file.read().strip())
            except FileNotFoundError:
                print("File not found.")
                continue
            res = test_candidate_seed(oracle, candidate_seed, candidate_seed)
            print("Candidate seed " + ("passed" if res else "failed") + " the test against the oracle.")
        else:
            print("\nInvalid operation selected. Please try again.")
            continue
        print("\nOperation completed. Check the generated files in ./files/")
        
if __name__ == "__main__":
    print("Welcome to the Seed Recovery Framework for MPCitH Signature Schemes!")
    print("If you want to exit at any point, press Ctrl+C.")
    print("The oracle will remain the same for all operations, so you can generate seeds and",
          "keys, introduce noise to the seeds, and test them against the same oracle instance.")
    main()