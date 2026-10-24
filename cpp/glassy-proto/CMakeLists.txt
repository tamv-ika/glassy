cmake_minimum_required(VERSION 3.28)
project(glassy_proto LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(EMSCRIPTEN)
  set(_glassy_server_default OFF)
else()
  set(_glassy_server_default ON)
endif()
option(GLASSY_PROTO_SERVER "Build the server-side sources" ${_glassy_server_default})
option(GLASSY_PROTO_TESTS "Build the tests" ON)
option(GLASSY_PROTO_SANITIZE "Build our targets and tests with ASan and UBSan (clang)" OFF)
option(GLASSY_PROTO_FUZZ "Build the libFuzzer targets in fuzz/ with ASan and UBSan (clang)" OFF)

if(GLASSY_PROTO_SANITIZE)
  # Global so gtest and the vendored libraries are instrumented consistently; nettle is a
  # system library and stays uninstrumented. No recovery: any report fails the test.
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer
    -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

if(GLASSY_PROTO_FUZZ)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "GLASSY_PROTO_FUZZ needs clang for C and C++ (libFuzzer)")
  endif()
  if(NOT GLASSY_PROTO_SERVER)
    message(FATAL_ERROR "GLASSY_PROTO_FUZZ needs GLASSY_PROTO_SERVER")
  endif()
  # Coverage instrumentation and sanitizers for every library; only the fuzz targets link the
  # libFuzzer main. No recovery: a sanitizer report is a crash the fuzzer must keep.
  add_compile_options(-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer
    -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

# Monocypher is third-party code: no -Werror, no warning flags.
add_library(glassy_monocypher STATIC third_party/monocypher/monocypher.c)
target_include_directories(glassy_monocypher PUBLIC third_party/monocypher)
target_compile_options(glassy_monocypher PRIVATE -ffunction-sections -fdata-sections)

add_library(glassy_proto_core STATIC src/error.cc src/varint.cc src/aead.cc src/base64.cc
  src/utf8.cc src/json_reader.cc src/connect_info.cc src/pn.cc src/packet_connect.cc
  src/packet_reply.cc src/packet_data.cc src/frame.cc src/message.cc)
target_include_directories(glassy_proto_core PUBLIC include PRIVATE src)
target_link_libraries(glassy_proto_core PUBLIC glassy_monocypher)
target_compile_options(glassy_proto_core PRIVATE
  -Wall -Wextra -Werror -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections)

# Size gate (tools/check_size.sh): a probe that references every public core function against an
# empty baseline. Static, stripped and gc-sections so only referenced code counts.
foreach(_t size_probe size_baseline)
  add_executable(${_t} EXCLUDE_FROM_ALL tools/${_t}.cc)
  target_compile_options(${_t} PRIVATE -Os -ffunction-sections -fdata-sections -fno-exceptions
    -fno-rtti)
  target_link_options(${_t} PRIVATE -static -Wl,--gc-sections -s)
endforeach()
target_link_libraries(size_probe PRIVATE glassy_proto_core)

if(GLASSY_PROTO_SERVER)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(NETTLE REQUIRED IMPORTED_TARGET nettle)

  # nettle is only included from src/sha256_nettle.cc.
  add_library(glassy_proto_server STATIC
    src/packet_server.cc src/server_ticket.cc src/ice.cc src/retry.cc src/trailer.cc src/wt.cc src/sha256_nettle.cc)
  target_include_directories(glassy_proto_server PUBLIC include PRIVATE src)
  target_link_libraries(glassy_proto_server PUBLIC glassy_proto_core PkgConfig::NETTLE)
  target_compile_options(glassy_proto_server PRIVATE
    -Wall -Wextra -Werror -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections)

  # Decode CLI for scripts/differential.sh; must print the same lines as crates/glassy-proto-cli.
  add_executable(glassy_proto_cli tools/proto_cli.cc)
  target_link_libraries(glassy_proto_cli PRIVATE glassy_proto_server)
  target_compile_options(glassy_proto_cli PRIVATE -Wall -Wextra -Werror)
endif()

if(GLASSY_PROTO_FUZZ)
  # Run with scripts/fuzz_smoke.sh.
  foreach(_f fuzz_native fuzz_frames fuzz_server_ticket fuzz_connect_info fuzz_retry fuzz_wt)
    add_executable(${_f} fuzz/${_f}.cc)
    target_link_libraries(${_f} PRIVATE glassy_proto_server)
    target_compile_options(${_f} PRIVATE -fsanitize=fuzzer -Wall -Wextra -Werror)
    target_link_options(${_f} PRIVATE -fsanitize=fuzzer)
  endforeach()
endif()

if(GLASSY_PROTO_TESTS)
  if(EMSCRIPTEN)
    # Tests only (the library above is already declared with -fno-exceptions): nlohmann_json
    # throws and gtest catches, so test code needs exceptions under Emscripten.
    add_compile_options(-fexceptions)
    add_link_options(-fexceptions)
    # NODERAWFS lets Node read the absolute GLASSY_VECTORS_DIR / GLASSY_FIXTURES_DIR paths.
    link_libraries(-sNODERAWFS=1 -sALLOW_MEMORY_GROWTH=1 -sEXIT_RUNTIME=1)
    if(NOT CMAKE_CROSSCOMPILING_EMULATOR)
      find_program(_glassy_node node REQUIRED)
      set(CMAKE_CROSSCOMPILING_EMULATOR "${_glassy_node}")
    endif()
  endif()
  include(FetchContent)
  # Git instead of release tarballs: the egress proxy blocks GitHub archive downloads.
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
    GIT_SHALLOW TRUE)
  FetchContent_Declare(nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.12.0
    GIT_SHALLOW TRUE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest nlohmann_json)
  enable_testing()

  get_filename_component(_glassy_root "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)

  add_library(glassy_proto_test_support STATIC tests/vectors.cc)
  target_include_directories(glassy_proto_test_support PUBLIC tests)
  target_link_libraries(glassy_proto_test_support PUBLIC glassy_proto_core
    nlohmann_json::nlohmann_json)
  target_compile_options(glassy_proto_test_support PRIVATE -Wall -Wextra -Werror)
  # Absolute paths so tests do not depend on the working directory ctest uses.
  target_compile_definitions(glassy_proto_test_support PUBLIC
    GLASSY_VECTORS_DIR="${_glassy_root}/vectors"
    GLASSY_FIXTURES_DIR="${_glassy_root}/crates/glassy-proto/tests/fixtures")

  add_executable(kat_test tests/kat_test.cc)
  target_link_libraries(kat_test PRIVATE glassy_proto_test_support GTest::gtest_main)
  target_compile_options(kat_test PRIVATE -Wall -Wextra -Werror)

  add_executable(base64_test tests/base64_test.cc)
  target_include_directories(base64_test PRIVATE src)
  target_link_libraries(base64_test PRIVATE glassy_proto_core GTest::gtest_main)
  target_compile_options(base64_test PRIVATE -Wall -Wextra -Werror)

  # Own binary: it replaces the global operator new to count allocations.
  add_executable(connect_info_test tests/connect_info_test.cc)
  target_include_directories(connect_info_test PRIVATE src)
  target_link_libraries(connect_info_test PRIVATE glassy_proto_test_support GTest::gtest_main)
  target_compile_options(connect_info_test PRIVATE -Wall -Wextra -Werror)

  include(GoogleTest)
  gtest_discover_tests(kat_test)
  gtest_discover_tests(base64_test)
  gtest_discover_tests(connect_info_test)

  # Core-only: must build and pass without the server target.
  add_executable(packet_core_test tests/packet_core_test.cc)
  target_link_libraries(packet_core_test PRIVATE glassy_proto_test_support GTest::gtest_main)
  target_compile_options(packet_core_test PRIVATE -Wall -Wextra -Werror)
  gtest_discover_tests(packet_core_test)

  add_executable(frame_test tests/frame_test.cc tests/message_test.cc)
  target_link_libraries(frame_test PRIVATE glassy_proto_test_support GTest::gtest_main)
  target_compile_options(frame_test PRIVATE -Wall -Wextra -Werror)
  gtest_discover_tests(frame_test)

  if(GLASSY_PROTO_SERVER)
    add_executable(server_test tests/server_ticket_test.cc tests/ice_test.cc tests/retry_test.cc
      tests/wt_test.cc)
    target_link_libraries(server_test PRIVATE glassy_proto_server glassy_proto_test_support
      GTest::gtest_main)
    target_compile_options(server_test PRIVATE -Wall -Wextra -Werror)
    gtest_discover_tests(server_test)

    add_executable(packet_server_test tests/packet_server_test.cc)
    target_link_libraries(packet_server_test PRIVATE glassy_proto_server
      glassy_proto_test_support GTest::gtest_main)
    target_compile_options(packet_server_test PRIVATE -Wall -Wextra -Werror)
    gtest_discover_tests(packet_server_test)
  endif()

  # The sweep also covers the server-side parsers when they are built.
  add_executable(robustness_test tests/robustness_test.cc)
  target_link_libraries(robustness_test PRIVATE glassy_proto_test_support GTest::gtest_main)
  if(GLASSY_PROTO_SERVER)
    target_link_libraries(robustness_test PRIVATE glassy_proto_server)
    target_compile_definitions(robustness_test PRIVATE GLASSY_PROTO_HAS_SERVER=1)
  endif()
  target_compile_options(robustness_test PRIVATE -Wall -Wextra -Werror)
  gtest_discover_tests(robustness_test)
endif()
