import random

from SchemeBridges.sdith_library_bridge import sdith_keygen

# Define constants for the different models
SDITH = 1
MIRATH = 2
MQOM = 3
PERK = 4
RYDE = 5


# ================================== Model-Agnostic Algorithms for Key Recovery ==================================
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
            
            # Flip the bit according to the probabilities alpha and beta
            if bit == 0: noisy_bit = 1 if random.random() < alpha else 0
            else: noisy_bit = 0 if random.random() < beta else 1
            
            # Construct the noisy byte by shifting and adding the noisy bit
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
    
    lambda_bytes = {1: 16, 3: 24, 5: 32}[security_level]
    
    if model == SDITH:
        # A zeroed pkseed is used when only skseed is known (oracle mode).
        # In practice the pkseed is stored inside the public key itself (first lambda_bytes).
        
        if isinstance(public_key, (bytes, bytearray)):
            # Extract the pkseed from the first lambda_bytes of the reference public key.
            known_pkseed = int.from_bytes(public_key[:lambda_bytes], byteorder='big')
        
        else:
            known_pkseed = 0  # unknown pkseed; will only match if pkseed happens to be zero
        
        candidate_pk, _ = sdith_keygen(security_level, candidate, known_pkseed, fast=1)
        
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
        public_key, private_key = sdith_keygen(security_level, skseed, pkseed, fast=1)
    
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