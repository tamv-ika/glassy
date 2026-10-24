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

# Monocypher is third-party code: no -Werror, no warning flags.
add_library(glassy_monocypher STATIC third_party/monocypher/monocypher.c)
target_include_directories(glassy_monocypher PUBLIC third_party/monocypher)
target_compile_options(glassy_monocypher PRIVATE -ffunction-sections -fdata-sections)

add_library(glassy_proto_core STATIC src/error.cc src/varint.cc src/aead.cc src/base64.cc)
target_include_directories(glassy_proto_core PUBLIC include PRIVATE src)
target_link_libraries(glassy_proto_core PUBLIC glassy_monocypher)
target_compile_options(glassy_proto_core PRIVATE
  -Wall -Wextra -Werror -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections)

if(GLASSY_PROTO_SERVER)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(NETTLE REQUIRED IMPORTED_TARGET nettle)

  # nettle is only included from src/sha256_nettle.cc.
  add_library(glassy_proto_server STATIC
    src/server_ticket.cc src/ice.cc src/retry.cc src/trailer.cc src/wt.cc src/sha256_nettle.cc)
  target_include_directories(glassy_proto_server PUBLIC include PRIVATE src)
  target_link_libraries(glassy_proto_server PUBLIC glassy_proto_core PkgConfig::NETTLE)
  target_compile_options(glassy_proto_server PRIVATE
    -Wall -Wextra -Werror -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections)
endif()

if(GLASSY_PROTO_TESTS)
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

  include(GoogleTest)
  gtest_discover_tests(kat_test)
  gtest_discover_tests(base64_test)

  if(GLASSY_PROTO_SERVER)
    add_executable(server_test tests/server_ticket_test.cc tests/ice_test.cc tests/retry_test.cc
      tests/wt_test.cc)
    target_link_libraries(server_test PRIVATE glassy_proto_server glassy_proto_test_support
      GTest::gtest_main)
    target_compile_options(server_test PRIVATE -Wall -Wextra -Werror)
    gtest_discover_tests(server_test)
  endif()
endif()
