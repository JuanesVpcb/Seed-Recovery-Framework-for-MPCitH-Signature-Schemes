import ctypes
import os
import platform

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

def sdith_keygen(security_level: int, skseed: bytes, pkseed: bytes, fast: int) -> tuple[bytes, bytes]:
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