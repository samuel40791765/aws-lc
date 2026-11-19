# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

# rust-phase0 experiment: build the crypto/rust staticlib with CMake-forced
# Cargo settings and fold it into one object, rust.o, that build_libcrypto()
# adds the way the FIPS build adds bcm.o. Consumers still link only libcrypto.
# Cargo discovery comes from the caracal PoC's cmake/cargo.cmake.

if(CMAKE_CONFIGURATION_TYPES)
  message(FATAL_ERROR "ENABLE_RUST does not support multi-config generators yet")
endif()
if(APPLE)
  message(FATAL_ERROR "ENABLE_RUST does not support Apple platforms yet")
endif()
if(CMAKE_CROSSCOMPILING)
  message(FATAL_ERROR "ENABLE_RUST does not support cross builds yet")
endif()

find_program(CARGO_EXECUTABLE NAMES cargo
             HINTS "$ENV{CARGO_HOME}/bin" "$ENV{HOME}/.cargo/bin")
find_program(RUSTC_EXECUTABLE NAMES rustc
             HINTS "$ENV{CARGO_HOME}/bin" "$ENV{HOME}/.cargo/bin")
if(NOT CARGO_EXECUTABLE OR NOT RUSTC_EXECUTABLE)
  message(FATAL_ERROR "ENABLE_RUST is set but cargo/rustc was not found. Install a "
                      "Rust toolchain or set CARGO_EXECUTABLE and RUSTC_EXECUTABLE.")
endif()
execute_process(COMMAND ${RUSTC_EXECUTABLE} -vV
  RESULT_VARIABLE rustc_result OUTPUT_VARIABLE rustc_vv ERROR_VARIABLE rustc_err
  OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_STRIP_TRAILING_WHITESPACE)
if(NOT rustc_result EQUAL 0 OR NOT rustc_vv)
  message(FATAL_ERROR "ENABLE_RUST: '${RUSTC_EXECUTABLE} -vV' failed: ${rustc_err}")
endif()
string(REGEX MATCH "^[^\n]*" RUSTC_VERSION_OUTPUT "${rustc_vv}")
message(STATUS "Found cargo: ${CARGO_EXECUTABLE}; rustc: ${RUSTC_EXECUTABLE} (${RUSTC_VERSION_OUTPUT})")
# The crate uses the 2024 edition, which needs rustc 1.85.
string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" RUSTC_VERSION "${RUSTC_VERSION_OUTPUT}")
if(RUSTC_VERSION VERSION_LESS 1.85)
  message(FATAL_ERROR "ENABLE_RUST needs rustc 1.85 or newer, for the 2024 edition; "
                      "found '${RUSTC_VERSION_OUTPUT}'")
endif()

# The partial link gets the C flags from the toolchain file or the user, such
# as -m32. AWS-LC adds its own flags after this file runs: with -fsanitize,
# clang links a sanitizer runtime into rust.o even with -nostdlib.
# -fno-sanitize=all, which GCC 4.8 lacks, keeps out one passed in CFLAGS.
if(CMAKE_HOST_WIN32)
  separate_arguments(RUST_LINK_C_FLAGS WINDOWS_COMMAND "${CMAKE_C_FLAGS}")
else()
  separate_arguments(RUST_LINK_C_FLAGS UNIX_COMMAND "${CMAKE_C_FLAGS}")
endif()
if(CMAKE_C_FLAGS MATCHES "-fsanitize=")
  list(APPEND RUST_LINK_C_FLAGS -fno-sanitize=all)
endif()

# Consumer-supplied rustc flags, the Rust analogue of CMAKE_C_FLAGS. Becomes
# CARGO_ENCODED_RUSTFLAGS, which replaces RUSTFLAGS and config-file rustflags.
set(RUST_FLAGS "" CACHE STRING "Extra rustc flags (semicolon-separated list)")
# Cargo passes RUST_FLAGS after the profile settings forced below, and rustc
# keeps the last of a repeated -C option: -Copt-level=0 brought panic data back.
set(forced_codegen "opt-level|lto|codegen-units|panic|debuginfo|debug-assertions|overflow-checks|incremental")
foreach(flag IN LISTS RUST_FLAGS)
  if(flag MATCHES "^(-C *|--codegen[= ]*)?(${forced_codegen})(=|$)" OR flag MATCHES "^-[Og]$")
    message(FATAL_ERROR "RUST_FLAGS must not contain '${flag}': CMake forces "
                        "opt-level, lto, codegen-units, panic, debug info and checks")
  endif()
endforeach()

# The C toolchain's objcopy makes Rust symbols local, on ELF and MinGW GCC.
if(WIN32 AND NOT CMAKE_C_COMPILER_ID STREQUAL "GNU")
  message(FATAL_ERROR "ENABLE_RUST does not support this Windows toolchain yet")
elseif(NOT CMAKE_OBJCOPY)
  message(FATAL_ERROR "ENABLE_RUST needs objcopy")
endif()

# cargo_add_rust_object(OUTPUT <rust.o> MANIFEST_PATH <Cargo.toml>
#                       LIB_NAME <name> EXPORTS <sym>...)
#
# Adds a custom command producing OUTPUT, in which only EXPORTS stay global.
# C code must declare EXPORTS with hidden visibility (crypto/rust/internal.h),
# which keeps them out of libcrypto's exports. Use OUTPUT as a source file of a
# target in the same directory.
function(cargo_add_rust_object)
  cmake_parse_arguments(arg "" "OUTPUT;MANIFEST_PATH;LIB_NAME" "EXPORTS" ${ARGN})
  get_filename_component(crate_dir "${arg_MANIFEST_PATH}" DIRECTORY)
  file(GLOB_RECURSE rust_sources "${crate_dir}/*.rs" "${crate_dir}/Cargo.toml" "${crate_dir}/Cargo.lock")

  set(target_dir "${AWSLC_BINARY_DIR}/cargo")
  # Always Cargo's release profile; CMake pins every setting that matters.
  set(staticlib "${target_dir}/release/${CMAKE_STATIC_LIBRARY_PREFIX}${arg_LIB_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX}")

  # Debug (or no build type) gets Rust's debug settings, anything else Release's.
  string(TOLOWER "${CMAKE_BUILD_TYPE}" build_type_lower)
  if(build_type_lower MATCHES "^(debug)?$")
    set(is_debug 1)
  else()
    set(is_debug 0)
  endif()
  set(rust_opt "$<${is_debug}:0>$<$<NOT:${is_debug}>:3>")
  set(rust_debug "$<${is_debug}:true>$<$<NOT:${is_debug}>:false>")

  # Forced settings (doc 3.2.1). --config outranks Cargo.toml and config files.
  set(P "profile.release")
  set(forced_config
    --config "${P}.opt-level=${rust_opt}"
    --config "${P}.lto=\"fat\""
    --config "${P}.codegen-units=1"
    --config "${P}.panic=\"abort\""
    --config "${P}.debug=${rust_debug}"
    --config "${P}.debug-assertions=${rust_debug}"
    --config "${P}.overflow-checks=${rust_debug}"
    --config "${P}.incremental=false"
    --config "build.rustc-wrapper=\"\""
    --config "build.rustc-workspace-wrapper=\"\"")
  # CARGO_ENCODED_RUSTFLAGS separates flags with 0x1f.
  string(ASCII 31 unit_sep)
  string(REPLACE ";" "${unit_sep}" encoded_rustflags "${RUST_FLAGS}")
  # RUSTC and RUSTC_WRAPPER env vars are read by Cargo directly, so pin them too.
  set(cargo_env ${CMAKE_COMMAND} -E env
    "RUSTC=${RUSTC_EXECUTABLE}"
    "RUSTC_WRAPPER="
    "RUSTC_WORKSPACE_WRAPPER="
    "CARGO_ENCODED_RUSTFLAGS=${encoded_rustflags}"
    --unset=RUSTFLAGS)

  # A partial link with `-u <export>` takes the crate object out of the
  # staticlib, plus only the members it needs (compiler_builtins helpers).
  # Every other symbol then becomes local.
  get_filename_component(output_dir "${arg_OUTPUT}" DIRECTORY)
  set(linked_obj "${output_dir}/rust_full.o")
  set(exports_file "${CMAKE_CURRENT_BINARY_DIR}/rust_exports.txt")
  set(export_syms "")
  set(undefined_args "")
  foreach(sym ${arg_EXPORTS})
    list(APPEND export_syms "${sym}")
    list(APPEND undefined_args -u "${sym}")
  endforeach()
  string(REPLACE ";" "\n" exports_text "${export_syms}")
  file(WRITE "${exports_file}" "${exports_text}\n")

  # The partial link runs through the C compiler, which tells the linker the
  # target: with only a library as input, lld 14 needs -m.
  set(partial_link ${CMAKE_C_COMPILER} -r -nostdlib ${RUST_LINK_C_FLAGS})
  set(fold_commands
    COMMAND ${partial_link} ${undefined_args} -o "${linked_obj}" "${staticlib}"
    COMMAND ${CMAKE_OBJCOPY} "--keep-global-symbols=${exports_file}" "${linked_obj}" "${arg_OUTPUT}")

  add_custom_command(
    OUTPUT "${arg_OUTPUT}"
    COMMAND ${cargo_env} ${CARGO_EXECUTABLE} build
      --locked --offline
      --manifest-path "${arg_MANIFEST_PATH}"
      --target-dir "${target_dir}"
      --release
      ${forced_config}
    ${fold_commands}
    DEPENDS ${rust_sources}
    COMMENT "Building Rust staticlib ${arg_LIB_NAME} into rust.o"
    USES_TERMINAL
    VERBATIM)
endfunction()
