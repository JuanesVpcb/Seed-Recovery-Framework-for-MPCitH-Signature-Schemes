from abc import ABC, abstractmethod

# Oracle generation class from abstract seed candidates and a public key for MPCitH algorithms - params and return {0, 1}

class MPCitHOracle(ABC):
    """Abstract base class for MPCitH oracle generation from seeds and public keys."""
    
    security_level: int  # Security level (1, 3, or 5) for the scheme
    params: dict  # Dictionary to hold scheme-specific parameters, such as seed sizes.
    
    @abstractmethod
    def seeds(self) -> tuple[bytes, bytes]:
        """Generate seed(s) for the scheme.
        
        Returns:
            tuple: Either one 2λ-sized master seed or two λ-sized seeds (secret and public).
        """
        pass
    
    @abstractmethod
    def expand(self, seeds: tuple[bytes, ...]) -> dict:
        """Expand the seed(s) according to scheme-specific requirements.
        
        Args:
            seeds: Seed(s) from seeds().
            
        Returns:
            dict: Expanded material from the seed(s).
        """
        pass
    
    @abstractmethod
    def proof(self, expanded_material: dict) -> bytes:
        """Generate zero-knowledge proof portion from expanded material.
        
        Args:
            expanded_material: Output from expand().
            
        Returns:
            bytes: The proof to verify seeds later. In all 5 models, the value 'y'.
        """
        pass
    
    @abstractmethod
    def verify(self, seeds: tuple[bytes, ...], y: bytes, expanded_material: dict) -> bytes:
        """Generate the final key using seeds, proof, and expanded material.
        
        Args:
            seeds: The tuple of seeds to verify.
            y: The proof generated in proof().
            expanded_material: Output from expand().

        Returns:
            bytes: The generated key.
        """
        pass
    
    @abstractmethod
    def keygen_from_seeds(self, skseed: bytes, pkseed: bytes) -> tuple[bytes, bytes]:
        """Generate the public and secret keys from the provided seeds.
        
        Args:
            skseed: The secret key seed (λ bytes).
            pkseed: The public key seed (λ bytes, or 0 if not used).
            
        Returns:
            tuple[bytes, bytes]: The generated public key and secret key.
        """
        pass
    
    @abstractmethod
    def get_seedpk(self, public_key: bytes) -> bytes:
        """Deserialize the public key to extract the pkseed and any other necessary components.
        
        Args:
            public_key: The public key bytes to deserialize.
            
        Returns:
            bytes: The extracted pkseed or relevant portion for key generation.
        """
        pass
    
    @abstractmethod
    def get_seedsk(self, private_key: bytes) -> bytes:
        """Deserialize the private key to extract the skseed and any other necessary components.
        
        Args:
            private_key: The private key bytes to deserialize.
            
        Returns:
            bytes: The extracted skseed or relevant portion for key generation.
        """
        pass
    
    @abstractmethod
    def get_y(self, public_key: bytes) -> bytes:
        """Extract the 'y' value from the expanded material for verification.
        
        Args:
            public_key: The public key bytes.
        
        Returns:
            bytes: The 'y' value for verification.
        """
        pass