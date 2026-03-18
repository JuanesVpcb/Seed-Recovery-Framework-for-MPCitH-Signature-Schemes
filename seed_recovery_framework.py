import random

from abstract_oracle import MPCitHOracle
from Schemes.sdith_algorithms import SDitHOracle

# Define constants for the different models
SDITH = 1
MIRATH = 2
MQOM = 3
PERK = 4
RYDE = 5

oracle: MPCitHOracle | None = None  # Global variable to hold the instantiated oracle for the selected model and security level

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
def option1(model_name: str) -> tuple:    
    pk, sk = oracle.seeds()  # Generate seeds and keys using the oracle for the selected model and security level
    skseed = oracle.get_seedsk(sk)  # Extract the skseed from the secret key
    pkseed = oracle.get_seedpk(pk)  # Extract the pkseed from the public key

    security_level = oracle.security_level
    
    # Save keys and seeds to unencrypted files (testing the algorithm, thus no encryption needed)
    with open(f"{model_name}_L{security_level}_skseed.pem", "w") as skseed_file:
        skseed_file.write(skseed.hex())
    if model_name != "MQOM":
        with open(f"{model_name}_L{security_level}_pkseed.pem", "w") as pkseed_file:
            pkseed_file.write(pkseed.hex())
    with open(f"{model_name}_L{security_level}_public_key.pem", "w") as public_key_file:
        public_key_file.write(pk.hex())
    with open(f"{model_name}_L{security_level}_private_key.pem", "w") as private_key_file:
        private_key_file.write(sk.hex())
    
    print(f"\nGenerated seeds and keys for {model_name} {security_level}:")
    print(f"skseed: {(skseed.hex())}")
    if model_name != "MQOM": print(f"pkseed: {pkseed.hex()}")
    print(f"public_key: {pk.hex()}")
    print(f"private_key: {sk.hex()}")
    
    return skseed, pkseed, pk, sk

def option2(model_name: str) -> None:
    # Get the alpha and beta values for the CBA bit-flip probabilities from the user, with defaults and validation
    while True:
        alpha = float(input("Enter the alpha (0 -> 1) value to use between 0 and 1 (default: 0.005): ") or 0.005)
        beta = float(input("Enter the beta (1 -> 0) value to use between 0 and 1 (default: 0.25): ") or 0.25)
        if not (0 <= beta <= 1) or not (0 <= alpha <= 1):
            print("Invalid beta or alpha value. Please enter a value between 0 and 1.")
            continue
        break

    # Open the file containing the candidate seed to introduce noise to, with validation and default file name based on the model and security level
    candidate_seed_f = input("\nEnter the name of the file with the seed to introduce noise to (blank for default): ")
    if candidate_seed_f == "":
        candidate_seed_f = f"{model_name}_L{oracle.security_level}_skseed.pem"  # Default file name for testing
    try:
        with open(candidate_seed_f, "r") as seed_file:
            candidate_seed = bytes.fromhex(seed_file.read().strip())
    except FileNotFoundError:
        print(f"File {candidate_seed_f} not found. Please check the file name and try again.")
        return
    except ValueError:
        print(f"File {candidate_seed_f} does not contain a valid bytes-coded seed. Please check the file contents and try again.")
        return
    
    
    noisy_candidate_seed = introduce_noise(candidate_seed, alpha, beta)
    print(f"Noisy candidate seed: {noisy_candidate_seed.hex()}")
    
    # Save the noisy candidate seed to a file for testing
    with open(f"{model_name}_L{oracle.security_level}_noisy_candidate_seed.pem", "w") as noisy_seed_file:
        noisy_seed_file.write(noisy_candidate_seed.hex())
        
    return noisy_candidate_seed


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
        security_level = int(input("Select the security level (1, 3, or 5): "))
        if security_level in [1, 3, 5]: break
        else: print("Invalid security level selected. Please try again.")
    
    # Instantiate the oracle for the selected model and security level (currently only SDITH supported)
    if model_input == SDITH: oracle = SDitHOracle(security_level=security_level, fast=True)
    else:
        print("Oracle generation for the selected model is not implemented yet.")
        return

    # ----------------------------- Operation selection -----------------------------
    while True:
        print("\nSelect the operation:")
        print("\t0: Exit the program")
        print("\t1: Generate random seed and keys")
        print("\t2: Intrduce noise to a candidate seed with CBA bit-flip probability values")
        print("\t3: Test a singular candidate seed")
        # TODO: Port the BBLM attack to the framework and add it as an option here (option 4)
        # TODO: Run options 1-4 
        operation_input = int(input("Enter the operation: "))
        
        # Exit the program
        if operation_input == 0:
            print("Exiting the program.")
            return

        # Generate random seed and keys
        elif operation_input == 1:
            _ = option1(model_input, model_name)

        # Test seed candidate with CBA bit-flip probability values
        elif operation_input == 2:
            _ = option2(model_name)

        elif operation_input == 3:
            # TODO: Implement the logic to test a candidate seed against the oracle algorithm for the selected model.
            print("\nTesting a candidate seed is not implemented yet.")
            pass
        
        elif operation_input == 4:
            # TODO: Implement the logic to run the BBLM attack for the selected model.
            print("\nRunning the BBLM attack is not implemented yet.")
            pass
        
        else:
            print("Invalid operation selected. Please try again.")
            continue
        
if __name__ == "__main__":
    print("Welcome to the Seed Recovery Framework for MPCitH Signature Schemes!")
    print("If you want to exit at any point, press Ctrl+C.")
    main()