import random

from abstract_oracle import MPCitHOracle
from Schemes.sdith_algorithms import SDitHOracle

# Define constants for the different models
SDITH = 1
MIRATH = 2
MQOM = 3
PERK = 4
RYDE = 5

# ================================== Model-Agnostic Algorithms for Key Recovery ==================================
def introduce_noise(seed: bytes, alpha: float, beta: float) -> bytes:
    """Introduces noise to the seed based on the specified alpha and beta parameters.
    Each bit of every byte is independently flipped: 0->1 with probability alpha,
    1->0 with probability beta."""
    noisy_bytes = []
    for byte in seed:
        noisy_byte = 0
        for i in range(7, -1, -1): # iterate bits MSB to LSB
            bit = (byte >> i) & 1
            
            # Flip the bit according to the probabilities alpha and beta
            if bit == 0: noisy_bit = 1 if random.random() < alpha else 0
            else: noisy_bit = 0 if random.random() < beta else 1
            
            # Construct the noisy byte by shifting and adding the noisy bit
            noisy_byte = (noisy_byte << 1) | noisy_bit
        noisy_bytes.append(noisy_byte)
    return bytes(noisy_bytes)


# =================================== User Interface for Testing the Algorithms ====================================
def option1(model_name: str, oracle: MPCitHOracle) -> tuple[bytes, bytes, bytes, bytes]:
    """Generates seeds and keys for the selected model and security level, saves them to files, and returns them as a tuple.
    
    Params:
        model_name: The name of the selected model (e.g., "SDITH").
        oracle: The instantiated oracle for the selected model and security level.
        
    Returns:
        A tuple containing the generated skseed, pkseed, public key, and private key as bytes.        
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
    with open(f"files/keys/{model_name}_L{security_level}_skseed.pem", "w") as skseed_file:
        skseed_file.write(skseed.hex())
    if model_name != "MQOM":
        with open(f"files/keys/{model_name}_L{security_level}_pkseed.pem", "w") as pkseed_file:
            pkseed_file.write(pkseed.hex())
    with open(f"files/keys/{model_name}_L{security_level}_public_key.pem", "w") as public_key_file:
        public_key_file.write(pk.hex())
    with open(f"files/keys/{model_name}_L{security_level}_private_key.pem", "w") as private_key_file:
        private_key_file.write(sk.hex())
    
    print(f"\nGenerated seeds and keys for {model_name} {security_level}:")
    print(f"skseed: {(skseed.hex())}")
    if model_name != "MQOM": print(f"pkseed: {pkseed.hex()}")
    print(f"public_key: {pk.hex()}")
    print(f"private_key: {sk.hex()}")
    
    return skseed, pkseed, sk, pk

def option2(model_name: str, oracle: MPCitHOracle, clean: bytes) -> tuple[bytes, str]:
    """Introduces noise to a candidate seed using CBA bit-flip probabilities and saves the noisy seed to a file.
    
    Params:
        model_name: The name of the selected model (e.g., "SDITH").
        oracle: The instantiated oracle for the selected model and security level.
        clean: The clean candidate seed as bytes.
        
    Returns:
        The noisy candidate seed as bytes.
    """
    
    # Get the alpha and beta values for the CBA bit-flip probabilities from the user, with defaults and validation
    while True:
        alpha = float(input("Enter the alpha (0 -> 1) value to use between 0 and 1 (default: 0.005): ") or 0.005)
        beta = float(input("Enter the beta (1 -> 0) value to use between 0 and 1 (default: 0.25): ") or 0.25)
        if not (0 <= beta <= 1) or not (0 <= alpha <= 1):
            print("Invalid beta or alpha value. Please enter a value between 0 and 1.")
            continue
        break

    if clean is not None:
        seed = clean
    else:
        # Open the file containing the candidate seed to introduce noise to, with validation and default file name based on the model and security level
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
    
    noisy_candidate_seed = introduce_noise(seed, alpha, beta)
    print(f"Noisy candidate seed: {noisy_candidate_seed.hex()}")
    
    # Save the noisy candidate seed to a file for testing
    noisy_file = f"files/noisy_seeds/{model_name}_L{oracle.security_level}_noisy_seed_{alpha:.3f}_{beta:.2f}.pem"
    with open(noisy_file, "w") as noisy_seed_file:
        noisy_seed_file.write(noisy_candidate_seed.hex())
        
    return noisy_candidate_seed, noisy_file

def option3(model_name: str, oracle: MPCitHOracle) -> bool:
    """Tests a singular candidate seed against the oracle algorithm for the selected model and security level.
    
    Params:
        model_name: The name of the selected model (e.g., "SDITH").
        oracle: The instantiated oracle for the selected model and security level.
        
    Returns:
        A boolean indicating whether the candidate seed passes the test.
    """
    
    # TODO: Implement the logic to test a candidate seed against the oracle algorithm for the selected model.
    print("\nTesting a candidate seed against the oracle algorithm is not implemented yet.")
    pass

def option4(model_name: str, oracle: MPCitHOracle) -> dict:
    """Runs the BBLM attack for the selected model and security level, returning the results as a dictionary.
    
    Params:
        model_name: The name of the selected model (e.g., "SDITH").
        oracle: The instantiated oracle for the selected model and security level.
        
    Returns:
        A dictionary containing the results of the BBLM attack.
    """
    # TODO: Implement the logic to run the BBLM attack for the selected model.
    print("\nRunning the BBLM attack is not implemented yet.")
    pass

def option5(model_name: str, oracle: MPCitHOracle) -> None:
    # TODO: Implement the logic to graph results for multiple candidate seeds and noise levels.
    print("\nGraphing results for multiple candidate seeds and noise levels is not implemented yet.")
    pass


# =================================== Main Function to Run the Console Interface ===================================
def main() -> None:
    # ------------------------------- Model selection -------------------------------
    while True:
        print("\nAvailable models:")
        print("\t1: SDITH")
        print("\t(Working on... MIRATH, MQOM, PERK, RYDE)")
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
    
    # Instantiate the oracle for the selected model and security level (currently only SDITH supported)
    oracle: MPCitHOracle = None
    if model_input == SDITH: oracle = SDitHOracle(security_level=security_level, fast=True)
    else:
        print("Oracle generation for the selected model is not implemented yet.")
        return
    
    # To keep track of generated seeds, keys, and test results for graphing in option 5
    history = {
        "skseed": b"",
        "pkseed": b"",
        "sk": b"",
        "pk": b"",
        "noisy_seed": b"",
        "noisy_seed_files": [],
        "bblm_results": [],
    }

    # ----------------------------- Operation selection -----------------------------
    while True:
        print("\nSelect the operation:")
        print("\t0: Exit the program")
        print("\t1: Generate random seed and keys")
        print("\t2: Intrduce noise to a candidate seed with CBA bit-flip probability values")
        print("\t3: Test a singular candidate seed")
        print("\t4: (Working on...) Run the BBLM attack")
        print("\t5: (Working on...) Graph results for multiple candidate seeds and noise levels")
        operation_input = int(input("Enter the operation: "))
        
        # Run through the options
        if operation_input == 0: 
            print("\nExiting the program.")
            return
        elif operation_input == 1: 
            res = option1(model_name, oracle)
            if res is not None:
                history["skseed"] = res[0]
                history["pkseed"] = res[1]
                history["sk"] = res[2]
                history["pk"] = res[3]
        elif operation_input == 2: 
            res = option2(model_name, oracle, history["skseed"])
            if res is not None:
                history["noisy_seed"] = res[0]
                history["noisy_seed_files"].append(res[1])
        elif operation_input == 3:
            _ = option3(model_name, oracle)
        elif operation_input == 4: 
            res = option4(model_name, oracle)
            if res is not None:
                history["bblm_results"].append(res)
        elif operation_input == 5: 
            option5(model_name, oracle)
        else:
            print("\nInvalid operation selected. Please try again.")
            continue
        
        print("\nOperation completed. Check the generated files in ./files/")
        
if __name__ == "__main__":
    print("Welcome to the Seed Recovery Framework for MPCitH Signature Schemes!")
    print("If you want to exit at any point, press Ctrl+C.")
    main()