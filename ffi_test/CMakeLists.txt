cmake_minimum_required(VERSION 3.20)
project(arsenic_test CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(ExternalProject)

# ── Locate cargo ──────────────────────────────────────────────────────────────
find_program(CARGO cargo REQUIRED
    HINTS "$ENV{HOME}/.cargo/bin"
    DOC   "Rust package manager")

# ── Fetch & build the Rust FFI crate from GitHub ─────────────────────────────
#
# If you already have the cryptyrust workspace on your machine, point
# -DCRYPTYRUST_ROOT=/path/to/cryptyrust at configure time and the clone step
# will be skipped.
#
# Otherwise CMake clones the repo into the build tree and runs cargo automatically.

if(DEFINED CRYPTYRUST_ROOT)
    # Developer shortcut: use local checkout, no network needed.
    set(FFI_LIB "${CRYPTYRUST_ROOT}/target/release/libarsenic_ffi.a")

    add_custom_command(
        OUTPUT  "${FFI_LIB}"
        COMMAND "${CARGO}" build --release -p arsenic_ffi
        WORKING_DIRECTORY "${CRYPTYRUST_ROOT}"
        COMMENT "cargo build --release -p arsenic_ffi (local)"
        VERBATIM
    )
    add_custom_target(rust_ffi DEPENDS "${FFI_LIB}")
else()
    # Stranger mode: fetch cryptyrust from GitHub then build the ffi crate.
    set(_CRYPTYRUST_EP_DIR "${CMAKE_BINARY_DIR}/_cryptyrust_src")
    set(FFI_LIB "${_CRYPTYRUST_EP_DIR}/target/release/libarsenic_ffi.a")

    ExternalProject_Add(cryptyrust_ep
        GIT_REPOSITORY  "https://github.com/Antidote1911/cryptyrust"
        GIT_TAG         "master"
        GIT_SHALLOW     TRUE
        SOURCE_DIR      "${_CRYPTYRUST_EP_DIR}"
        CONFIGURE_COMMAND ""
        BUILD_COMMAND   "${CARGO}" build --release -p arsenic_ffi
        BUILD_IN_SOURCE TRUE
        INSTALL_COMMAND ""
        BUILD_BYPRODUCTS "${FFI_LIB}"
    )
    add_custom_target(rust_ffi DEPENDS cryptyrust_ep)
endif()

set(FFI_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/cryptyrust.h")

# ── Optional: regenerate the C header with cbindgen ───────────────────────────
#
# Requires cbindgen in PATH or ~/.cargo/bin.
# Only regenerated when ffi/src/lib.rs changes.
option(REGEN_HEADER "Regenerate cryptyrust.h with cbindgen" OFF)

if(REGEN_HEADER)
    find_program(CBINDGEN cbindgen
        HINTS "$ENV{HOME}/.cargo/bin"
        DOC   "cbindgen header generator")

    if(CBINDGEN)
        add_custom_command(
            OUTPUT  "${FFI_HEADER}"
            COMMAND "${CBINDGEN}"
                    --config  "${CRYPTYRUST_ROOT}/ffi/cbindgen.toml"
                    --crate   arsenic_ffi
                    --output  "${FFI_HEADER}"
            WORKING_DIRECTORY "${CRYPTYRUST_ROOT}"
            DEPENDS "${CRYPTYRUST_ROOT}/ffi/src/lib.rs"
                    "${CRYPTYRUST_ROOT}/ffi/cbindgen.toml"
            COMMENT "Regenerating cryptyrust.h"
            VERBATIM
        )
        add_custom_target(ffi_header DEPENDS "${FFI_HEADER}")
    else()
        message(WARNING "cbindgen not found — skipping header regeneration")
    endif()
endif()

# ── C++ test executable ───────────────────────────────────────────────────────
add_executable(arsenic_test main.cpp)

target_include_directories(arsenic_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"   # picks up cryptyrust.h
)

target_link_libraries(arsenic_test PRIVATE "${FFI_LIB}")

# Rust's standard library needs these system libraries on each platform
if(UNIX AND NOT APPLE)
    # Linux: pthreads, dynamic linker, math
    target_link_libraries(arsenic_test PRIVATE pthread dl m)
elseif(APPLE)
    # macOS: Security framework (used by the Rust runtime for random numbers)
    target_link_libraries(arsenic_test PRIVATE "-framework Security")
endif()
# Windows/MSVC: Rust links bcrypt.lib / ntdll.lib automatically

add_dependencies(arsenic_test rust_ffi)
if(REGEN_HEADER AND CBINDGEN)
    add_dependencies(arsenic_test ffi_header)
endif()

# ── Quick test target: encrypt then decrypt a 1 MiB synthetic file ────────────
add_custom_target(run_test
    COMMAND "${CMAKE_COMMAND}" -E echo "--- generating 1 MiB test file ---"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_BINARY_DIR}/test_data"
    # dd if=/dev/urandom produces a random file
    COMMAND dd if=/dev/urandom
                bs=1024 count=1024
                of="${CMAKE_BINARY_DIR}/test_data/sample.bin"
    COMMAND "${CMAKE_COMMAND}" -E echo "--- encrypting ---"
    COMMAND "${CMAKE_BINARY_DIR}/arsenic_test"
            encrypt
            "${CMAKE_BINARY_DIR}/test_data/sample.bin"
            "test_password_1234"
    COMMAND "${CMAKE_COMMAND}" -E echo "--- decrypting ---"
    COMMAND "${CMAKE_BINARY_DIR}/arsenic_test"
            decrypt
            "${CMAKE_BINARY_DIR}/test_data/sample.bin.arsn"
            "test_password_1234"
    COMMAND "${CMAKE_COMMAND}" -E echo "--- comparing ---"
    COMMAND "${CMAKE_COMMAND}" -E compare_files
            "${CMAKE_BINARY_DIR}/test_data/sample.bin"
            "${CMAKE_BINARY_DIR}/test_data/sample.bin"
    DEPENDS arsenic_test
    COMMENT "Encrypt → decrypt round-trip test"
    VERBATIM
)
