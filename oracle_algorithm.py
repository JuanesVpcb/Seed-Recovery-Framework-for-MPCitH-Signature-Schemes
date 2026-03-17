import ctypes
import os
import platform
import random

# Define constants for the different models
SDITH = 1
MIRATH = 2
MQOM = 3
PERK = 4
RYDE = 5

# ========================== SDitH C Bridge (via ctypes) ==========================
def _load_sdith_bridge():
    """Loads the compiled libsdith_keygen shared library from SDitH-Library/build."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if platform.system() == "Darwin":
        ext = "dylib"
    elif platform.system() == "Windows":
        ext = "dll"
    else:
        ext = "so"
    candidates = [
        os.path.join(script_dir, "SDitH-Library", "build", f"libsdith_keygen.{ext}"),
        os.path.join(script_dir, f"libsdith_keygen.{ext}"),
    ]
    if platform.system() == "Windows":
        candidates.append(os.path.join(script_dir, "SDitH-Library", "build", "sdith_keygen.dll"))
        candidates.append(os.path.join(script_dir, "sdith_keygen.dll"))

    lib_path = next((p for p in candidates if os.path.exists(p)), None)
    if lib_path is None:
        lib_path = candidates[0]
        raise FileNotFoundError(
            f"SDitH bridge library not found at {lib_path}.\n"
            "Run ./setup_sdith_local.sh and then bash ./build_sdith_[variant].sh to build it."
        )
    lib = ctypes.CDLL(lib_path)

    # uint64_t sdith_bridge_public_key_bytes(int security_level, int fast)
    lib.sdith_bridge_public_key_bytes.restype  = ctypes.c_uint64
    lib.sdith_bridge_public_key_bytes.argtypes = [ctypes.c_int, ctypes.c_int]

    # uint64_t sdith_bridge_secret_key_bytes(int security_level, int fast)
    lib.sdith_bridge_secret_key_bytes.restype  = ctypes.c_uint64
    lib.sdith_bridge_secret_key_bytes.argtypes = [ctypes.c_int, ctypes.c_int]

    # int sdith_bridge_keygen(int security_level, int fast,
    #                         const uint8_t* skseed, const uint8_t* pkseed,
    #                         uint8_t* out_public_key, uint8_t* out_secret_key)
    lib.sdith_bridge_keygen.restype  = ctypes.c_int
    lib.sdith_bridge_keygen.argtypes = [
        ctypes.c_int, ctypes.c_int,
        ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_char_p, ctypes.c_char_p,
    ]
    return lib

_sdith_lib = None  # lazy-loaded on first use

def _get_sdith_lib():
    global _sdith_lib
    if _sdith_lib is None:
        _sdith_lib = _load_sdith_bridge()
    return _sdith_lib


def _sdith_keygen(security_level: int, skseed: bytes, pkseed: bytes, fast: int) -> tuple[bytes, bytes]:
    """
    Calls the C bridge to run SDitH key generation.
    Returns (public_key_bytes, secret_key_bytes).
    """
    lib = _get_sdith_lib()

    pk_len = lib.sdith_bridge_public_key_bytes(security_level, fast)
    sk_len = lib.sdith_bridge_secret_key_bytes(security_level, fast)

    pk_buf = ctypes.create_string_buffer(pk_len)
    sk_buf = ctypes.create_string_buffer(sk_len)

    ret = lib.sdith_bridge_keygen(
        security_level, fast,
        skseed, pkseed,
        pk_buf, sk_buf
    )
    if ret != 0:
        raise RuntimeError("sdith_bridge_keygen returned an error.")

    return bytes(pk_buf), bytes(sk_buf)


# ========================== Model-Agnostic Algorithms for Key Recovery ==========================
def random_seed_generation(length: int) -> bytes:
    """Generates a random seed of the specified length in bits. Usually, the length 
    would be determined by the security parameters of the model. For these, the ranges
    are typically between 128 and 256 bits."""
    
    return int(''.join(random.choice('01') for _ in range(length)), 2).to_bytes((length + 7) // 8, byteorder='big')

def introduce_noise(seed: bytes, alpha: float, beta: float) -> bytes:
    """Introduces noise to the seed based on the specified alpha and beta parameters.
    Each bit of every byte is independently flipped: 0->1 with probability alpha,
    1->0 with probability beta."""
    noisy_bytes = []
    for byte in seed:
        noisy_byte = 0
        for i in range(7, -1, -1): # iterate bits MSB to LSB
            bit = (byte >> i) & 1
            if bit == 0:
                noisy_bit = 1 if random.random() < alpha else 0
            else:
                noisy_bit = 0 if random.random() < beta else 1
            noisy_byte = (noisy_byte << 1) | noisy_bit
        noisy_bytes.append(noisy_byte)
    return bytes(noisy_bytes)

def oracle_algorithm(model: int, candidate: bytes, public_key: bytes | int, security_level: int = 1) -> bool:
    """Implements a modular oracle algorithm to determine whether the seed
    expands correctly into the correct public-private key pair for the 
    specified model.
    
    For SDitH, `candidate` is the skseed integer and `public_key` is either
    a bytes object or an integer representing the expected public key.
    `security_level` must be 1, 3, or 5 (default: 1)."""
    
    if model == SDITH:
        lambda_bytes = {1: 16, 3: 24, 5: 32}[security_level]
        # A zeroed pkseed is used when only skseed is known (oracle mode).
        # In practice the pkseed is stored inside the public key itself (first lambda_bytes).
        if isinstance(public_key, (bytes, bytearray)):
            # Extract the pkseed from the first lambda_bytes of the reference public key.
            known_pkseed = int.from_bytes(public_key[:lambda_bytes], byteorder='big')
        else:
            known_pkseed = 0  # unknown pkseed; will only match if pkseed happens to be zero
        candidate_pk, _ = _sdith_keygen(security_level, candidate, known_pkseed, fast=1)
        if isinstance(public_key, (bytes, bytearray)): return candidate_pk == bytes(public_key)
        return int.from_bytes(candidate_pk, byteorder='big') == public_key
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
    return False

def key_generation(model: int, skseed: bytes, pkseed: bytes = 0, security_level: int = 1) -> tuple:
    """Generates a public-private key pair based on the provided seed and model.
    
    For SDitH, returns (public_key_bytes, secret_key_bytes).
    `security_level` must be 1, 3, or 5 (default: 1).
    For all other models the function returns integer placeholders (not yet implemented)."""
    
    public_key = 0  # Placeholder for the generated public key
    private_key = 0 # Placeholder for the generated private key
    
    if model == SDITH:
        fast = 1 if input("\nUse FAST parameter sets for SDitH? (y/n, default: y): ").lower() == 'y' else 0
        public_key, private_key = _sdith_keygen(security_level, skseed, pkseed, fast=fast)
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


# ========================= User Interface for Testing the Algorithms ==========================
def option1(model: int, model_name: str) -> tuple:
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
    pkseed = random_seed_generation(pkseed_length) if pkseed_length > 0 else 0
    public_key, private_key = key_generation(model, skseed, pkseed, security_level)
    
    # For SDitH the keys are raw bytes; convert to hex for storage/display
    pk_display = public_key.hex() if isinstance(public_key, (bytes, bytearray)) else str(public_key)
    sk_display = private_key.hex() if isinstance(private_key, (bytes, bytearray)) else str(private_key)

    # Save keys and seeds to unencrypted files (testing the algorithm, thus no encryption needed)
    with open(f"{model_name}_L{security_level}_skseed.pem", "w") as skseed_file:
        skseed_file.write(skseed.hex())
    if pkseed_length > 0:
        with open(f"{model_name}_L{security_level}_pkseed.pem", "w") as pkseed_file:
            pkseed_file.write(pkseed.hex())
    with open(f"{model_name}_L{security_level}_public_key.pem", "w") as public_key_file:
        public_key_file.write(pk_display)
    with open(f"{model_name}_L{security_level}_private_key.pem", "w") as private_key_file:
        private_key_file.write(sk_display)
    
    print(f"\nGenerated seeds and keys for {model_name} {security_level}:")
    print(f"skseed: {(skseed.hex())}")
    if pkseed_length > 0:
        print(f"pkseed: {pkseed.hex()}")
    print(f"public_key: {pk_display}")
    print(f"private_key: {sk_display}")
    
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