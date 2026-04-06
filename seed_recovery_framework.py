import os
import json
from concurrent.futures import ProcessPoolExecutor
import matplotlib.pyplot as plt

from abstract_oracle import MPCitHOracle
from Schemes.sdith_algorithms import SDitHOracle
from Schemes.perk_algorithms import PERKOracle
from Schemes.ryde_algorithms import RYDEOracle
from Schemes.mqom_algorithms import MQOMOracle
from Schemes.mirath_algorithms import MirathOracle
from helper_algorithms import introduce_noise, extract_seedpk_and_y, load_noisy_seeds_from_file, ranked_seed_candidates_from_noisy

# Define constants for the different models
SDITH = 1
MIRATH = 2
MQOM = 3
PERK = 4
RYDE = 5


_WORKER_ORACLE = None
_WORKER_SEEDPK = None
_WORKER_Y = None
_WORKER_ALPHA = None
_WORKER_BETA = None
_WORKER_W = None
_WORKER_MU = None
_WORKER_MAX_CANDIDATES = None


# ================================= Internal Functions for BBLM Attack Worker Processes ==================================
def _build_oracle(model_name: str, security_level: int) -> MPCitHOracle:
    if model_name == "SDITH":
        return SDitHOracle(security_level=security_level, fast=True)
    if model_name == "PERK":
        return PERKOracle(security_level=security_level, fast=True)
    if model_name == "RYDE":
        return RYDEOracle(security_level=security_level, fast=True)
    if model_name == "MQOM":
        return MQOMOracle(security_level=security_level)
    if model_name == "MIRATH":
        return MirathOracle(security_level=security_level, fast=True)
    raise ValueError(f"Unknown model name: {model_name}")


def _initialize_bblm_worker(model_name: str, security_level: int, seedpk: bytes, y: bytes, alpha: float, beta: float, w: int, mu: int, max_candidates: int) -> None:
    global _WORKER_ORACLE, _WORKER_SEEDPK, _WORKER_Y, _WORKER_ALPHA, _WORKER_BETA, _WORKER_W, _WORKER_MU, _WORKER_MAX_CANDIDATES
    _WORKER_ORACLE = _build_oracle(model_name, security_level)
    _WORKER_SEEDPK = seedpk
    _WORKER_Y = y
    _WORKER_ALPHA = alpha
    _WORKER_BETA = beta
    _WORKER_W = w
    _WORKER_MU = mu
    _WORKER_MAX_CANDIDATES = max_candidates


def _run_bblm_on_noisy_seed(noisy_seed: bytes) -> tuple[str, bool]:
    ranked_candidates = ranked_seed_candidates_from_noisy(
        noisy_seed=noisy_seed,
        alpha=_WORKER_ALPHA,
        beta=_WORKER_BETA,
        w=_WORKER_W,
        mu=_WORKER_MU,
        max_candidates=_WORKER_MAX_CANDIDATES,
    )

    recovered = False
    for candidate_seed in ranked_candidates:
        derived_pk, _ = _WORKER_ORACLE.keygen_from_seeds(candidate_seed, _WORKER_SEEDPK)
        if _WORKER_ORACLE.get_y(derived_pk) == _WORKER_Y:
            recovered = True
            break

    return noisy_seed.hex(), recovered


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
        beta_string = "0.03, 0.05, 0.10, 0.15, 0.20, 0.25"
        beta_values = input("Enter the beta (1 -> 0) values to use between 0 and 1 (default: 0.03, 0.05, 0.10, 0.15, 0.20, 0.25): ") or beta_string
        betas = []
        for beta_str in beta_string.split(","):
            try:
                beta_val = float(beta_str.strip())
                if beta_val < 0 or beta_val > 1:
                    print(f"beta value {beta_val} is out of range [0,1]. Skipping this value.")
                    continue
                betas.append(beta_val)
            except ValueError:
                print(f"Invalid beta value '{beta_str}'. Please enter numeric values. Skipping this value.")
                continue
        break
    
    sample_count = 100 # int(input("How many noisy seeds to generate with these parameters? (default: 100): ") or 100)
    # while True:
    #     if sample_count > 0: break
    #     print("The number of noisy seeds must be a positive integer. Please try again.")

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
    
    # Get the parameters for the BBLM attack from the user, with defaults and validation
    alpha = 0.001
    w = 8
    mu = 16
    max_candidates = 1000
    #while True:
    #    alpha = float(input("Enter alpha (0->1) used for noisy seed (default 0.001): ") or 0.001)
    #    if alpha < 0 or alpha > 1:
    #        print("alpha must be in [0,1]. Please try again.")
    #        continue
    #    break

    #while True:
    #    w = int(input("Enter chunk width w in bits (default 8): ") or 8)
    #    mu = int(input("Enter top-mu candidates per chunk (default 16): ") or 16)
    #    max_candidates = int(input("Enter max seed candidates to test (default 1000): ") or 1000)
    #    if w <= 0 or mu <= 0 or max_candidates <= 0:
    #        print("w, mu, and max_candidates must be positive integers. Please try again.")
    #        continue
    #    break
    
    print(f"\nRunning BBLM-style reconstruction for {model_name} L{oracle.security_level} (w={w}, mu={mu}, max={max_candidates}, alpha={alpha})...")
    
    # Get the beta values to test from the user, with validation and support for multiple comma-separated values
    beta_strings = "0.03, 0.05, 0.10, 0.15, 0.20, 0.25"
    betas = input("Enter beta values to test, separated by commas (default: 0.03, 0.05, 0.10, 0.15, 0.20, 0.25): ") or beta_strings
    beta_values = []
    for beta_str in betas.split(","):
        try:
            beta = float(beta_str.strip())
            if beta < 0 or beta > 1:
                print(f"beta value {beta} is out of range [0,1]. Skipping this value.")
                continue
            beta_values.append(beta)
        except ValueError:
            print(f"Invalid beta value '{beta_str}'. Please enter numeric values. Skipping this value.")
    
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
        "w": w,
        "mu": mu,
        "max_candidates": max_candidates
    }
    beta_results = []
        
    seedpk, y = extract_seedpk_and_y(oracle, public_key)
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
        recoveries = 0
        _initialize_bblm_worker(model_name, oracle.security_level, seedpk, y, alpha, beta, w, mu, max_candidates)

        worker_count = min(len(noisy_seeds), max(1, (os.cpu_count() or 2) - 1))
        if worker_count <= 1:
            for noisy_seed in noisy_seeds:
                print(" + Testing seed: " + noisy_seed.hex())
                recovered_hex, recovered = _run_bblm_on_noisy_seed(noisy_seed)
                per_seed_results[recovered_hex] = recovered
                if recovered:
                    recoveries += 1
        else:
            print(f"   Using {worker_count} worker processes for this beta.")
            with ProcessPoolExecutor(
                max_workers=worker_count,
                initializer=_initialize_bblm_worker,
                initargs=(model_name, oracle.security_level, seedpk, y, alpha, beta, w, mu, max_candidates),
            ) as executor:
                for recovered_hex, recovered in executor.map(_run_bblm_on_noisy_seed, noisy_seeds, chunksize=8):
                    per_seed_results[recovered_hex] = recovered
                    if recovered:
                        recoveries += 1

        seeds_processed = len(noisy_seeds)
        recovery_probability = (recoveries / seeds_processed) if seeds_processed > 0 else 0.0
        beta_results.append({
            "beta": beta,
            "seeds_processed": seeds_processed,
            "recoveries": recoveries,
            "recovery_probability": recovery_probability,
            "per_seed_results": per_seed_results,
        })
        print(
            f"beta={beta:.2f}: recovered {recoveries}/{seeds_processed} seeds "
            f"(p={recovery_probability:.4f})"
        )
        
    results["beta_results"] = beta_results
    
    os.makedirs("files/bblm", exist_ok=True)
    with open(f"files/bblm/{model_name}_L{oracle.security_level}_recovery.json", "w") as f:
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
    bblm_file = f"{bblm_dir}/{model_name}_L{oracle.security_level}_recovery.json"
    try:
        with open(bblm_file, "r") as f:
            results = json.load(f)
    except Exception as exc:
        print(f"Could not read BBLM results file: {exc}. Run option 3 to generate results first and try again.")
        return

    # Plot the recovery probability against beta values using matplotlib, with appropriate labels and title based on the model, 
    # security level, and parameters used in the BBLM attack
    
    # TODO: Add more detailed plots, such as recovery probability distributions in a box plot with max values, quarters and outliers
    # per beta, as well as compiling from multiple runs.
    plt.figure(figsize=(10, 6))
    plt.plot(
        [br["beta"] for br in results["beta_results"]],
        [br["recovery_probability"] for br in results["beta_results"]],
        marker="o"
    )
    plt.title(f"BBLM Attack Results for {model_name} L{oracle.security_level}, " +
              f"alpha={results['alpha']}, w={results['w']}, mu={results['mu']}, " +
              f"max. candidates={results['max_candidates']}")
    plt.xlabel("Beta")
    plt.ylabel("Recovery Probability")
    plt.grid(True)
    
    os.makedirs("files/figures", exist_ok=True)
    plt.savefig(f"files/figures/{model_name}_L{oracle.security_level}_recovery_plot.png")
    plt.show()
    
def option5(oracle: MPCitHOracle, candidate_seed: bytes, public_key: bytes) -> bool:
    """Tests a singular candidate seed against the oracle algorithm for the selected model and security level.
    
    Params:
        model_name: The name of the selected model (e.g., "SDITH").
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