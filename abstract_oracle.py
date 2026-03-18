from abc import ABC, abstractmethod

# Oracle generation class from abstract seed candidates and a public key for MPCitH algorithms - params and return {0, 1}

class MPCitHOracle(ABC):
    """Abstract base class for MPCitH oracle generation from seeds and public keys."""
    
    @abstractmethod
    def seeds(self) -> tuple:
        """Generate seed(s) for the scheme.
        
        Returns:
            tuple: Either one 2λ-sized master seed or two λ-sized seeds (secret and public).
        """
        pass
    
    @abstractmethod
    def expand(self, seeds: tuple) -> dict:
        """Expand the seed(s) according to scheme-specific requirements.
        
        Args:
            seeds: Seed(s) from seeds().
            
        Returns:
            dict: Expanded material from the seed(s).
        """
        pass
    
    @abstractmethod
    def proof(self, expanded_material: dict) -> bytes:
        """Generate zero-knowledge proof from expanded material.
        
        Args:
            expanded_material: Output from expand().
            
        Returns:
            bytes: The proof to verify seeds later.
        """
        pass
    
    @abstractmethod
    def verify(self, seeds: tuple, y: bytes, expanded_material: dict) -> bytes:
        """Generate the final key using seeds, proof, and expanded material.
        
        Args:
            seeds: Original seed(s).
            y: The proof generated in proof().
            expanded_material: Output from expand().

        Returns:
            bytes: The generated key.
        """
        pass