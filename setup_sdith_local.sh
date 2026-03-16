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

set -e

# Defaults
EXTERNAL_SDITH_BASE="../SDitH-v2/Reference_Implementation"
VARIANT="cat1_fast"
SHOW_HELP=0

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--path)
            EXTERNAL_SDITH_BASE="$2"
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
LOCAL_LIB="$REPO_ROOT/SDitH-Library/sdith_${VARIANT}"
mkdir -p "$LOCAL_LIB"/{src,lib/{aes,sha3/opt64,sha3/plain32},wrapper,build}

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

# Move bridge file into wrapper/ (if it exists at repo root)
echo "Setting up wrapper/ with bridge file..."
if [ -f "$REPO_ROOT/sdith_keygen_bridge.c" ]; then
    mv "$REPO_ROOT/sdith_keygen_bridge.c" "$LOCAL_LIB/wrapper/sdith_keygen_bridge.c"
    echo "Moved sdith_keygen_bridge.c to SDitH-Library/sdith_${VARIANT}/wrapper/"
fi

# Create wrapper header
cat > "$LOCAL_LIB/wrapper/sdith_keygen_bridge.h" << 'EOF'
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

echo "Created wrapper/sdith_keygen_bridge.h"

# Create CMakeLists.txt for the local library
cat > "$LOCAL_LIB/CMakeLists.txt" << 'EOF'
cmake_minimum_required(VERSION 3.10)
project(sdith_local)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Default build type" FORCE)
endif()

set(CMAKE_C_FLAGS_DEBUG "-O0 -g3 -Wall -Werror")
set(CMAKE_C_FLAGS_RELEASE "-O3 -g3 -Wall -Werror -DNDEBUG")
enable_language(ASM)

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
target_link_libraries(vole sha3 aes m)
target_compile_definitions(vole PRIVATE ONLY_REF_IMPLEMENTATION)
target_include_directories(vole PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Keygen bridge shared library
add_library(sdith_keygen SHARED wrapper/sdith_keygen_bridge.c)
target_link_libraries(sdith_keygen PRIVATE vole)
target_include_directories(sdith_keygen PRIVATE src)
target_compile_definitions(sdith_keygen PRIVATE ONLY_REF_IMPLEMENTATION)

# Set install names for macOS
set_target_properties(sdith_keygen PROPERTIES
    BUILD_RPATH "@loader_path"
    INSTALL_RPATH "@loader_path"
)

# Output to build directory
set_target_properties(sdith_keygen PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/build"
)
EOF

echo "Created local CMakeLists.txt"

# Create build script for this specific variant
cat > "$REPO_ROOT/build_sdith_${VARIANT}.sh" << 'EOF'
#!/usr/bin/env bash
# build_sdith_VARIANT.sh
# Builds the local vendored SDitH library for VARIANT

set -e

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

cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=10.13 \
    .

cmake --build build --config Release

DYLIB="$LOCAL_LIB/build/libsdith_keygen.dylib"
SO="$LOCAL_LIB/build/libsdith_keygen.so"

if [ -f "$DYLIB" ]; then
    echo "✓ Built: $DYLIB"
elif [ -f "$SO" ]; then
    echo "✓ Built: $SO"
else
    echo "ERROR: Build failed"
    exit 1
fi

echo "=== Build complete ==="
EOF

# Replace VARIANT placeholder in build script
sed -i '' "s/VARIANT/$VARIANT/g" "$REPO_ROOT/build_sdith_${VARIANT}.sh"
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
echo "  $LOCAL_LIB/build/libsdith_keygen.dylib  (macOS)"
echo "or"
echo "  $LOCAL_LIB/build/libsdith_keygen.so     (Linux)"
echo ""
echo "To vendor another variant, run:"
echo "  bash setup_sdith_local.sh -v cat3_fast"
echo "  bash setup_sdith_local.sh -v cat5_fast"