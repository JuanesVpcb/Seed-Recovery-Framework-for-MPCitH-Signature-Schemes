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


def _closest_supported_beta(beta: float) -> float:
    """Map any beta to the closest default beta (e.g., 0.5 -> 0.25)."""
    return min(DEFAULT_BETAS, key=lambda b: (abs(b - beta), b))


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
    W = _effective_profile_length_bits(model_name, oracle)
    W_key = min((128, 192, 256), key=lambda w: abs(w - W))
    beta_key = _closest_supported_beta(beta)

    profile = DEFAULT_B2_PROFILES[W_key][beta_key].copy()
    source = f"static_default:W{W_key}_beta{beta_key:.2f}"
    if abs(beta_key - beta) > 1e-12:
        source += f"_from_beta{beta:.2f}"
    return profile, source


def _process_noisy_seed_for_option3(
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
    """Derive a candidate budget from Model_Prediction.py using Btime/Bmemory."""
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
def option1(model_name: str, oracle: MPCitHOracle) -> None:
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
    
    pk, sk = oracle.keygen_from_seeds(skseed, pkseed)  # Generate the public and secret keys from the seeds using the oracle's keygen_from_seeds method
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

def option2(model_name: str, oracle: MPCitHOracle) -> None:
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
    
    sample_count = int(input("How many noisy seeds to generate with these parameters? (default: 20): ") or 20)
    while True:
        if sample_count > 0: break
        print("The number of noisy seeds must be a positive integer. Please try again.")
        sample_count = int(input("How many noisy seeds to generate with these parameters? (default: 20): ") or 20)

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
    
def option3(model_name: str, oracle: MPCitHOracle) -> None:
    """Runs the BBLM attack for the selected model and security level, saving the results to a json file.
    
    Params:
        model_name: The name of the selected model (e.g., "SDITH").
        oracle: The instantiated oracle for the selected model and security level.
    """
    
    # Keep parameter selection compact: one defaults question plus one optional custom line.
    use_defaults = (input("\nUse defaults? (y/n): ").strip().lower() or "y")
    if use_defaults in ("y", "yes"):
        alpha = 0.001
        beta_values = DEFAULT_BETAS
        print(f"Using defaults from BBLM configuration: alpha={alpha}, betas={beta_values}")
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
        candidate_mode = "okea"
    elif candidate_policy == "l":
        max_candidates_cap = 2 << 19
        candidate_mode = "lightweight"
    else:
        max_candidates_cap = 2 << 13
        candidate_mode = "beam"
    
    print(f"\nRunning BBLM-style reconstruction for {model_name} L{oracle.security_level}...")
    
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
            recovered = _process_noisy_seed_for_option3(
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
            print(f"      Processed seed ({noisy_hex}). Recovered? {recovered} in {(time_ns() - t_init) / 1e6:.3f}ms.")

        seeds_processed = len(noisy_seeds)
        candidate_limit_avg = (sum(per_seed_candidate_limits) / len(per_seed_candidate_limits)) if per_seed_candidate_limits else 0.0
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

def option4(model_name: str, oracle: MPCitHOracle) -> None:
    """Graphs the results of multiple candidate seeds and noise levels for the selected model and security level.
    
    Params:
        model_name: The name of the selected model (e.g., "SDITH").
        oracle: The instantiated oracle for the selected model and security level.
    """
    
    # Load files with BBLM results for the selected model and security level, with validation
    bblm_dir = "files/bblm"
    if not os.path.exists(bblm_dir):
        print(f"No BBLM results found for {model_name} L{oracle.security_level}. Run option 3 to generate results first and try again.")
        return
    bblm_file = f"{bblm_dir}/{model_name}_L{oracle.security_level}_recovery_lightweight.json"
    try:
        with open(bblm_file, "r") as f:
            results = json.load(f)
    except Exception as exc:
        print(f"Could not read BBLM results file: {exc}. Run option 3 to generate results first and try again.")
        return

    # Load matplotlib lazily to keep memory lower during attack runs.
    import matplotlib.pyplot as plt

    # Plot the recovery probability against beta values using matplotlib, with appropriate labels and title based on the model, 
    # security level, and parameters used in the BBLM attack
    plt.figure(figsize=(10, 6))
    plt.plot(
        [br["beta"] for br in results["beta_results"]],
        [br["recovery_probability"] for br in results["beta_results"]],
        marker="o"
    )
    plt.title(
        f"BBLM Attack Results for {model_name} L{oracle.security_level}, "
        f"alpha={results['alpha']}, w={results['w']}, mu={results['mu']}"
    )
    plt.xlabel("Beta")
    plt.ylabel("Recovery Probability")
    plt.grid(True)
    
    os.makedirs("files/figures", exist_ok=True)
    plt.savefig(f"files/figures/{model_name}_L{oracle.security_level}_recovery_plot.png")
    plt.show()
    
def option5(oracle: MPCitHOracle, candidate_seed: bytes, public_key: bytes) -> bool:
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
        print("\t3: MQOM")
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
        elif operation_input == 1: option1(model_name, oracle)
        elif operation_input == 2: option2(model_name, oracle)
        elif operation_input == 3: option3(model_name, oracle)
        elif operation_input == 4: option4(model_name, oracle)
        elif operation_input == 5:
            candidate_seed_file = input("\nEnter the name of the file with the candidate seed to test (blank for default): ")
            if candidate_seed_file == "":
                candidate_seed_file = f"files/keys/{model_name}_L{oracle.security_level}_skseed.pem"  # Default file name for testing
            try:
                with open(candidate_seed_file, "r") as seed_file:
                    candidate_seed = bytes.fromhex(seed_file.read().strip())
            except FileNotFoundError:
                print("File not found.")
                continue
            res = option5(oracle, candidate_seed, candidate_seed)
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