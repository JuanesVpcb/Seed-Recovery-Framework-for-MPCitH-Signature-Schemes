import random

# Define constants for the different models
SDITH = 1
MIRATH = 2
MQOM = 3
PERK = 4
RYDE = 5

def random_seed_generation(length: int) -> str:
    """Generates a random seed of the specified length in bits. Usually, the length 
    would be determined by the security parameters of the model. For these, the ranges
    are typically between 128 and 256 bits."""
    
    return ''.join(random.choice('01') for _ in range(length))

def introduce_noise(seed: str, alpha: float, beta: float) -> str:
    """Introduces noise to the seed based on the specified alpha and beta parameters."""
    noisy_seed = []
    for bit in seed:
        if bit == '0':
            # Flip 0 to 1 with probability alpha
            if random.random() < alpha:
                noisy_seed.append('1')
            else:
                noisy_seed.append('0')
        elif bit == '1':
            # Flip 1 to 0 with probability beta
            if random.random() < beta:
                noisy_seed.append('0')
            else:
                noisy_seed.append('1')
        else:
            raise ValueError("Invalid bit in seed. Seed should only contain '0' and '1'.")
    return ''.join(noisy_seed)

def oracle_algorithm(model: int, candidate: str, public_key: str) -> bool:
    """Implements a modular oracle algorithm to determine whether the seed
    expands correctly into the correct public-private key pair for the 
    specified model."""
    
    reconstructed_public_key = '' # Saves the reconstructed public key from the candidate seed
    
    if model == SDITH:
        # TODO: Implement the logic to reconstruct the public key from the candidate seed
        # for SDitH
        pass
    elif model == MIRATH:
        print("Not implemented yet for MIRATH model.")
        pass
    elif model == MQOM:
        print("Not implemented yet for MQOM model.")
        pass
    elif model == PERK:
        print("Not implemented yet for PERK model.")
        pass
    elif model == RYDE:
        print("Not implemented yet for RYDE model.")
        pass
    else:
        raise ValueError("Invalid model specified.")
    
    # Return True if the seed is valid, False otherwise
    return reconstructed_public_key == public_key

def key_generation(model: int, skseed: str, pkseed: str = "") -> tuple[str, str]:
    """Generates a public-private key pair based on the provided seed and model."""
    
    public_key = ''  # Placeholder for the generated public key
    private_key = '' # Placeholder for the generated private key
    
    if model == SDITH:
        # TODO: Implement the logic to generate the public and private keys from the seed 
        # for SDitH
        pass
    elif model == MIRATH:
        print("Not implemented yet for MIRATH model.")
        pass
    elif model == MQOM:
        print("Not implemented yet for MQOM model.")
        pass
    elif model == PERK:
        print("Not implemented yet for PERK model.")
        pass
    elif model == RYDE:
        print("Not implemented yet for RYDE model.")
        pass
    else:
        raise ValueError("Invalid model specified.")
    
    return (public_key, private_key)  # Return a tuple of (public_key, private_key)

def option1(model: int, model_name: str) -> None:
    security_level = 0
    while True:
        print("\nSelect the security level (L1, L3, L5)")
        security_level = int(input("Enter the security level (write 1, 3, or 5): "))
        if security_level not in [1, 3, 5]:
            print("Invalid security level selected. Please try again.")
            continue
        else:
            break
    
    # Length of the seeds in bits based on the security level
    length = {1: 128, 3: 192, 5: 256}[security_level]
    
    # MQOM uses a single master seed that is twice the length of the security level
    skseed_length = length if model != MQOM else 2 * length
    pkseed_length = length if model != MQOM else 0
        
    # Logic applied to all models (except MQOM, which only uses a single master seed)
    skseed = random_seed_generation(skseed_length)
    pkseed = random_seed_generation(pkseed_length) if pkseed_length > 0 else ""
    public_key, private_key = key_generation(model, skseed, pkseed)
    
    # Save keys and seeds to unencrypted files (testing the algorithm, thus no encryption needed)
    with open(f"{model_name}_L{security_level}_skseed.pem", "w") as skseed_file:
        skseed_file.write(skseed)
    if pkseed_length > 0:
        with open(f"{model_name}_L{security_level}_pkseed.pem", "w") as pkseed_file:
            pkseed_file.write(pkseed)
    with open(f"{model_name}_L{security_level}_public_key.pem", "w") as public_key_file:
        public_key_file.write(public_key)
    with open(f"{model_name}_L{security_level}_private_key.pem", "w") as private_key_file:
        private_key_file.write(private_key)
    
    print(f"Generated seeds and keys for {model_name} {security_level}:")
    print(f"skseed: {skseed}")
    if pkseed_length > 0:
        print(f"pkseed: {pkseed}")
    print(f"public_key: {public_key}")
    print(f"private_key: {private_key}")
    
def option2(model: int, model_name: str, alpha: float, beta: float) -> None:
    candidate_seed = input("\nEnter the name of the file with the seed to introduce noise to (blank for default name): ")
    noisy_candidate_seed = introduce_noise(candidate_seed, alpha, beta)
    print(f"Noisy candidate seed: {noisy_candidate_seed}")
    
    # Save the noisy candidate seed to a file for testing
    with open(f"{model_name}_noisy_candidate_seed.pem", "w") as noisy_seed_file:
        noisy_seed_file.write(noisy_candidate_seed)

def main() -> None:
    # ------------------------------- Model selection -------------------------------
    while True:
        print("\nAvailable models:")
        print("\t1: SDITH")
        print("\t(Working on... MIRATH, MQOM, PERK, RYDE)")
        model_input = int(input("Select the model to test (0 to exit): "))
        if model_input == 0:
            print("Exiting the program.")
            return
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
    
    # ----------------------------- Operation selection -----------------------------
    while True:
        print("\nSelect the operation:")
        print("\t0: Exit the program")
        print("\t1: Generate random seed and keys")
        print("\t2: Intrduce noise to a candidate seed with CBA bit-flip probability values")
        print("\t3: Test a candidate seed")
        operation_input = int(input("Enter the operation: "))
        if operation_input not in [0, 1, 2, 3]:
            print("Invalid operation selected. Please try again.")
            continue
        else: 
            break
    
    # ------------ Switch mechanism for the selected model and operation ------------
    # Exit
    if operation_input == 0:
        print("Exiting the program.")
        return
    
    # Generate random seed and keys
    elif operation_input == 1:
        option1(model_input, model_name)
    
    # Test seed candidate with CBA bit-flip probability values
    elif operation_input == 2:
        alpha = 0.005
        print(("\nAlpha (0 -> 1) value to use: 0.005"))
        beta = float(input("Enter the beta (1 -> 0) value to use (between 0 and 1): "))
        if not (0 <= beta <= 1):
            print("Invalid beta value. Please enter a value between 0 and 1.")
            return
        print(f"Beta (1 -> 0) value to use: {beta}")
        option2(model_input, model_name, alpha, beta)
        
if __name__ == "__main__":
    print("Welcome to the Seed Recovery Framework for MPCitH Signature Schemes!")
    main()