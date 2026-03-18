from model_agnostic_algorithms import introduce_noise, random_seed_generation, key_generation

# Define constants for the different models
SDITH = 1
MIRATH = 2
MQOM = 3
PERK = 4
RYDE = 5

# =================================== User Interface for Testing the Algorithms ====================================
def option1(model: int, model_name: str) -> tuple:
    security_level = 1  # Default security level (L1)
    while True:
        print("\nSelect the security level (L1, L3, L5)")
        security_level = input("Enter the security level (write 1, 3, or 5). Default (L1): ")
        if security_level != "": security_level = int(security_level)
        if security_level not in [1, 3, 5]:
            print("Invalid security level selected. Please try again.")
            continue
        else:
            break
    
    # Length of the seeds in bits based on the security level (lambda)
    length = {1: 128, 3: 192, 5: 256}[security_level]
    
    # MQOM uses a single master seed that is twice the length of the security level
    skseed_length = length if model != MQOM else 2 * length
    pkseed_length = length if model != MQOM else 0
        
    # Logic applied to all models (except MQOM, which only uses a single master seed)
    skseed = random_seed_generation(skseed_length)
    pkseed = random_seed_generation(pkseed_length) if pkseed_length > 0 else 0
    public_key, private_key = key_generation(model, skseed, pkseed, security_level)

    # Save keys and seeds to unencrypted files (testing the algorithm, thus no encryption needed)
    with open(f"{model_name}_L{security_level}_skseed.pem", "w") as skseed_file:
        skseed_file.write(skseed.hex())
    if pkseed_length > 0:
        with open(f"{model_name}_L{security_level}_pkseed.pem", "w") as pkseed_file:
            pkseed_file.write(pkseed.hex())
    with open(f"{model_name}_L{security_level}_public_key.pem", "w") as public_key_file:
        public_key_file.write(public_key.hex())
    with open(f"{model_name}_L{security_level}_private_key.pem", "w") as private_key_file:
        private_key_file.write(private_key.hex())
    
    print(f"\nGenerated seeds and keys for {model_name} {security_level}:")
    print(f"skseed: {(skseed.hex())}")
    if pkseed_length > 0: print(f"pkseed: {pkseed.hex()}")
    print(f"public_key: {public_key.hex()}")
    print(f"private_key: {private_key.hex()}")
    
    return skseed, pkseed, public_key, private_key
    
def option2(model_name: str, alpha: float, beta: float) -> None:
    candidate_seed_f = input("\nEnter the name of the file with the seed to introduce noise to (blank for default): ")
    if candidate_seed_f == "":
        candidate_seed_f = f"{model_name}_L1_skseed.pem"  # Default file name for testing
    try:
        with open(candidate_seed_f, "r") as seed_file:
            candidate_seed = bytes.fromhex(seed_file.read().strip())
    except FileNotFoundError:
        print(f"File {candidate_seed_f} not found. Please check the file name and try again.")
        return
    except ValueError:
        print(f"File {candidate_seed_f} does not contain a valid integer seed. Please check the file contents and try again.")
        return
    noisy_candidate_seed = introduce_noise(candidate_seed, alpha, beta)
    print(f"Noisy candidate seed: {noisy_candidate_seed.hex()}")
    
    # Save the noisy candidate seed to a file for testing
    with open(f"{model_name}_noisy_candidate_seed.pem", "w") as noisy_seed_file:
        noisy_seed_file.write(noisy_candidate_seed.hex())
        
    return noisy_candidate_seed


# =================================== Main Function to Run the Console Interface ===================================
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
        print("\t3: Test a singular candidate seed")
        # TODO: Port the BBLM attack to the framework and add it as an option here (option 4)
        # TODO: Run options 1-4 
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
        _ = option1(model_input, model_name)
    
    # Test seed candidate with CBA bit-flip probability values
    elif operation_input == 2:
        alpha = 0.005
        print(("\nAlpha (0 -> 1) value to use: 0.005"))
        beta = float(input("Enter the beta (1 -> 0) value to use (between 0 and 1): "))
        if not (0 <= beta <= 1):
            print("Invalid beta value. Please enter a value between 0 and 1.")
            return
        print(f"Beta (1 -> 0) value to use: {beta}")
        _ = option2(model_name, alpha, beta)
        
    elif operation_input == 3:
        # TODO: Implement the logic to test a candidate seed against the oracle algorithm for the selected model.
        print("\nTesting a candidate seed is not implemented yet.")
        pass
    
    elif operation_input == 4:
        # TODO: Implement the logic to run the BBLM attack for the selected model.
        print("\nRunning the BBLM attack is not implemented yet.")
        pass
        
if __name__ == "__main__":
    print("Welcome to the Seed Recovery Framework for MPCitH Signature Schemes!")
    main()