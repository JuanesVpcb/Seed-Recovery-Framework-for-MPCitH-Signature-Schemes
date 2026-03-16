#!/usr/bin/env bash
# setup_sdith_local.sh
# 
# Sets up a local vendored SDitH library inside the Seed-Recovery-Framework
# repository, copying all required sources from the external reference implementation.
#
# Usage:
#   bash setup_sdith_local.sh [options]
#
# Options:
#   -p, --path PATH          Path to external SDitH-v2 Reference_Implementation folder
#                            (default: ../SDitH-v2/Reference_Implementation)
#   -v, --variant VARIANT    SDitH implementation variant: cat1_fast, cat3_fast, cat5_fast
#                            (default: cat1_fast)
#   -h, --help               Show this help message

set -euo pipefail

# Defaults
EXTERNAL_SDITH_BASE_REL="../SDitH-v2/Reference_Implementation"
VARIANT="cat1_fast"
SHOW_HELP=0

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--path)
            EXTERNAL_SDITH_BASE_REL="$2"
            shift 2
            ;;
        -v|--variant)
            VARIANT="$2"
            shift 2
            ;;
        -h|--help)
            SHOW_HELP=1
            shift
            ;;
        *)
            echo "ERROR: Unknown option: $1"
            SHOW_HELP=1
            break
            ;;
    esac
done

# Show help if requested or on error
if [ $SHOW_HELP -eq 1 ]; then
    cat << 'EOF'
setup_sdith_local.sh - Vendor SDitH implementation into local repository

Usage:
  bash setup_sdith_local.sh [options]

Options:
  -p, --path PATH          Path to external SDitH-v2 Reference_Implementation folder
                           (default: ../SDitH-v2/Reference_Implementation)
  -v, --variant VARIANT    SDitH implementation variant:
                           - cat1_fast (default)
                           - cat3_fast
                           - cat5_fast
  -h, --help               Show this help message

Examples:
  # Use defaults (cat1_fast, relative path)
  bash setup_sdith_local.sh

  # Vendor cat3_fast with absolute path
  bash setup_sdith_local.sh -v cat3_fast -p /path/to/SDitH-v2/Reference_Implementation

  # Vendor cat5_fast
  bash setup_sdith_local.sh -v cat5_fast

EOF
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ "$EXTERNAL_SDITH_BASE_REL" = /* ]]; then
    EXTERNAL_SDITH_BASE="$EXTERNAL_SDITH_BASE_REL"
else
    EXTERNAL_SDITH_BASE="$REPO_ROOT/$EXTERNAL_SDITH_BASE_REL"
fi
EXTERNAL_SDITH="$EXTERNAL_SDITH_BASE/sdith_${VARIANT}"

# Validate variant
case "$VARIANT" in
    cat1_fast|cat3_fast|cat5_fast)
        ;;
    *)
        echo "ERROR: Invalid variant '$VARIANT'"
        echo "Valid options: cat1_fast, cat3_fast, cat5_fast"
        exit 1
        ;;
esac

# Check external source exists
if [ ! -d "$EXTERNAL_SDITH" ]; then
    echo "ERROR: External SDitH reference not found at:"
    echo "  $EXTERNAL_SDITH"
    echo ""
    echo "Try: bash setup_sdith_local.sh --help"
    exit 1
fi

echo "=== Setting up local SDitH-Library ==="
echo "Variant:  $VARIANT"
echo "Source:   $EXTERNAL_SDITH"
echo ""

# Create directory structure
SHARED_BRIDGE_DIR="$REPO_ROOT/SDitH-Library/wrapper"
SHARED_BUILD_DIR="$REPO_ROOT/SDitH-Library/build"
LOCAL_LIB="$REPO_ROOT/SDitH-Library/sdith_${VARIANT}"
mkdir -p "$LOCAL_LIB"/{src,lib/{aes,sha3/opt64,sha3/plain32},build}
mkdir -p "$SHARED_BRIDGE_DIR" "$SHARED_BUILD_DIR"

echo "Created directories under $LOCAL_LIB"

# Copy src/ files (29 files)
echo "Copying src/ (29 files)..."
cp "$EXTERNAL_SDITH/src"/*.{c,h,cpp} "$LOCAL_LIB/src/" 2>/dev/null || true

# Copy lib/aes/ files (13 files)
echo "Copying lib/aes/ (13 files)..."
cp "$EXTERNAL_SDITH/lib/aes"/*.{c,h,impl.h} "$LOCAL_LIB/lib/aes/" 2>/dev/null || true

# Copy lib/sha3/ root files
echo "Copying lib/sha3/ root files..."
cp "$EXTERNAL_SDITH/lib/sha3"/*.{c,h,inc} "$LOCAL_LIB/lib/sha3/" 2>/dev/null || true
cp "$EXTERNAL_SDITH/lib/sha3"/{Makefile,config.h,align.h,brg_endian.h,endian_compat.h,macros.h,SnP-Relaned.h,s390_cpacf.h} "$LOCAL_LIB/lib/sha3/" 2>/dev/null || true

# Copy lib/sha3/opt64/ files
echo "Copying lib/sha3/opt64/..."
cp "$EXTERNAL_SDITH/lib/sha3/opt64"/* "$LOCAL_LIB/lib/sha3/opt64/" 2>/dev/null || true

# Copy lib/sha3/plain32/ files
echo "Copying lib/sha3/plain32/..."
cp "$EXTERNAL_SDITH/lib/sha3/plain32"/* "$LOCAL_LIB/lib/sha3/plain32/" 2>/dev/null || true

echo "Copied all source files."

# Copy CMakeLists.txt from lib folders
echo "Copying CMakeLists.txt files..."
cp "$EXTERNAL_SDITH/lib/aes/CMakeLists.txt" "$LOCAL_LIB/lib/aes/" 2>/dev/null || true
cp "$EXTERNAL_SDITH/lib/sha3/CMakeLists.txt" "$LOCAL_LIB/lib/sha3/" 2>/dev/null || true

# Create a shared bridge source/header under SDitH-Library
echo "Setting up shared bridge in SDitH-Library/wrapper/..."
cat > "$SHARED_BRIDGE_DIR/sdith_keygen_bridge.c" << 'EOF'
/**
 * sdith_keygen_bridge.c
 *
 * Bridge exposing SDitH key generation to Python.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sdith_signature.h"
#include "sdith_keygen_bridge.h"

static const signature_parameters* pick_params(int security_level, int fast) {
    if (fast) {
        if (security_level == 1) return &CAT1_FAST_PARAMETERS;
        if (security_level == 3) return &CAT3_FAST_PARAMETERS;
        if (security_level == 5) return &CAT5_FAST_PARAMETERS;
    } else {
        if (security_level == 1) return &CAT1_SHORT_PARAMETERS;
        if (security_level == 3) return &CAT3_SHORT_PARAMETERS;
        if (security_level == 5) return &CAT5_SHORT_PARAMETERS;
    }
    return NULL;
}

int sdith_bridge_keygen(int security_level, int fast,
                        const uint8_t* skseed, const uint8_t* pkseed,
                        uint8_t* out_public_key, uint8_t* out_secret_key) {
    const signature_parameters* params = pick_params(security_level, fast);
    uint8_t* entropy = NULL;
    uint8_t* tmp_space = NULL;
    uint64_t lambda_bytes;
    uint64_t tmp_bytes;

    if (!params || !skseed || !pkseed || !out_public_key || !out_secret_key) {
        return -1;
    }

    lambda_bytes = params->lambda >> 3;

    /* entropy = pkseed || skseed (required by sdith_keygen) */
    entropy = (uint8_t*)malloc(2 * lambda_bytes);
    if (!entropy) {
        return -1;
    }
    memcpy(entropy, pkseed, lambda_bytes);
    memcpy(entropy + lambda_bytes, skseed, lambda_bytes);

    tmp_bytes = sdith_keygen_tmp_bytes(params);
    tmp_space = (uint8_t*)malloc(tmp_bytes);
    if (!tmp_space) {
        free(entropy);
        return -1;
    }

    sdith_keygen(params, out_secret_key, out_public_key, entropy, tmp_space);

    free(tmp_space);
    free(entropy);
    return 0;
}

uint64_t sdith_bridge_public_key_bytes(int security_level, int fast) {
    const signature_parameters* params = pick_params(security_level, fast);
    if (!params) return 0;
    return sdith_public_key_bytes(params);
}

uint64_t sdith_bridge_secret_key_bytes(int security_level, int fast) {
    const signature_parameters* params = pick_params(security_level, fast);
    if (!params) return 0;
    return sdith_secret_key_bytes(params);
}
EOF
echo "Created SDitH-Library/wrapper/sdith_keygen_bridge.c"

# Create wrapper header
cat > "$SHARED_BRIDGE_DIR/sdith_keygen_bridge.h" << 'EOF'
#ifndef SDITH_KEYGEN_BRIDGE_H
#define SDITH_KEYGEN_BRIDGE_H

#include <stdint.h>

/**
 * sdith_bridge_keygen
 * Generates an SDitH key pair from externally provided seeds.
 *
 * @param security_level  1, 3, or 5
 * @param fast            1 = FAST parameters, 0 = SHORT parameters
 * @param skseed          pointer to secret key seed (lambda/8 bytes)
 * @param pkseed          pointer to public key seed (lambda/8 bytes)
 * @param out_public_key  output buffer for public key
 * @param out_secret_key  output buffer for secret key
 * @return 0 on success, -1 on error
 */
int sdith_bridge_keygen(int security_level, int fast,
                        const uint8_t* skseed, const uint8_t* pkseed,
                        uint8_t* out_public_key, uint8_t* out_secret_key);

uint64_t sdith_bridge_public_key_bytes(int security_level, int fast);
uint64_t sdith_bridge_secret_key_bytes(int security_level, int fast);

#endif
EOF

echo "Created SDitH-Library/wrapper/sdith_keygen_bridge.h"

# Create CMakeLists.txt for the local library
cat > "$LOCAL_LIB/CMakeLists.txt" << 'EOF'
cmake_minimum_required(VERSION 3.10)
project(sdith_local)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Default build type" FORCE)
endif()

enable_language(ASM)

if(MSVC)
    set(CMAKE_C_FLAGS_DEBUG "/Od /Zi /W4")
    set(CMAKE_C_FLAGS_RELEASE "/O2 /DNDEBUG")
else()
    set(CMAKE_C_FLAGS_DEBUG "-O0 -g3 -Wall -Werror")
    set(CMAKE_C_FLAGS_RELEASE "-O3 -g3 -Wall -Werror -DNDEBUG")
endif()

# Build SHA3 library
add_subdirectory(lib/sha3)

# Build AES library
add_subdirectory(lib/aes)

# Main VOLE/SDitH library
set(VOLE_SRCS
    src/commons.c
    src/sdith_prng.c
    src/gf256.c
    src/gf192.c
    src/matrix_vector_products_f2.c
    src/matrix_transpose_f2.c
    src/ggm.c
    src/vole_expansion.c
    src/piop_circuit.c
    src/gf128.c
    src/rsd.c
    src/sdith_signature.c
    src/sdith_signature_parameters.c
    src/vole_to_piop.c
    src/vole_parameters.cpp
)

add_library(vole STATIC ${VOLE_SRCS})
if(MSVC)
    target_link_libraries(vole PRIVATE sha3 aes)
else()
    target_link_libraries(vole PRIVATE sha3 aes m)
endif()
target_compile_definitions(vole PRIVATE ONLY_REF_IMPLEMENTATION)
target_include_directories(vole PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Keygen bridge shared library
add_library(sdith_keygen SHARED ../wrapper/sdith_keygen_bridge.c)
target_link_libraries(sdith_keygen PRIVATE vole)
target_include_directories(sdith_keygen PRIVATE src ../wrapper)
target_compile_definitions(sdith_keygen PRIVATE ONLY_REF_IMPLEMENTATION)

# Set install names for macOS
if(APPLE)
    set_target_properties(sdith_keygen PROPERTIES
        BUILD_RPATH "@loader_path"
        INSTALL_RPATH "@loader_path"
    )
endif()

# Output to build directory
set_target_properties(sdith_keygen PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../build"
)
EOF

echo "Created local CMakeLists.txt"

# Create build script for this specific variant
cat > "$REPO_ROOT/build_sdith_${VARIANT}.sh" << 'EOF'
#!/usr/bin/env bash
# build_sdith_VARIANT.sh
# Builds the local vendored SDitH library for VARIANT

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
VARIANT="VARIANT"
LOCAL_LIB="$REPO_ROOT/SDitH-Library/sdith_${VARIANT}"

if [ ! -d "$LOCAL_LIB" ]; then
    echo "ERROR: Local SDitH library not found at $LOCAL_LIB"
    echo "Run: bash setup_sdith_local.sh -v $VARIANT"
    exit 1
fi

echo "=== Building local SDitH keygen library ($VARIANT) ==="
cd "$LOCAL_LIB"

UNAME="$(uname -s)"
if [ "$UNAME" = "Darwin" ]; then
    cmake -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_OSX_DEPLOYMENT_TARGET=10.13 \
        .
else
    cmake -B build \
        -DCMAKE_BUILD_TYPE=Release \
        .
fi

cmake --build build --config Release

DYLIB="$REPO_ROOT/SDitH-Library/build/libsdith_keygen.dylib"
SO="$REPO_ROOT/SDitH-Library/build/libsdith_keygen.so"
DLL="$REPO_ROOT/SDitH-Library/build/libsdith_keygen.dll"
DLL_NO_LIB="$REPO_ROOT/SDitH-Library/build/sdith_keygen.dll"

if [ -f "$DYLIB" ]; then
    echo "✓ Built: $DYLIB"
elif [ -f "$SO" ]; then
    echo "✓ Built: $SO"
elif [ -f "$DLL" ]; then
    echo "✓ Built: $DLL"
elif [ -f "$DLL_NO_LIB" ]; then
    echo "✓ Built: $DLL_NO_LIB"
else
    echo "ERROR: Build failed"
    exit 1
fi

echo "=== Build complete ==="
EOF

# Replace VARIANT placeholder in build script (portable across macOS/Linux/Git-Bash)
if [ "$(uname -s)" = "Darwin" ]; then
    sed -i '' "s/VARIANT/$VARIANT/g" "$REPO_ROOT/build_sdith_${VARIANT}.sh"
else
    sed -i "s/VARIANT/$VARIANT/g" "$REPO_ROOT/build_sdith_${VARIANT}.sh"
fi
chmod +x "$REPO_ROOT/build_sdith_${VARIANT}.sh"
echo "Created build_sdith_${VARIANT}.sh"

echo ""
echo "=== Setup complete! ==="
echo ""
echo "Next steps:"
echo "  1. cd $REPO_ROOT"
echo "  2. bash build_sdith_${VARIANT}.sh"
echo ""
echo "The local shared library will be built at:"
echo "  $REPO_ROOT/SDitH-Library/build/libsdith_keygen.dylib  (macOS)"
echo "or"
echo "  $REPO_ROOT/SDitH-Library/build/libsdith_keygen.so     (Linux)"
echo "or"
echo "  $REPO_ROOT/SDitH-Library/build/libsdith_keygen.dll    (Windows)"
echo ""
echo "To vendor another variant, run:"
echo "  bash setup_sdith_local.sh -v [variant]"