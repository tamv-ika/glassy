cmake_minimum_required(VERSION 3.28)
project(s4_wt_ngtcp2 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GNUTLS REQUIRED IMPORTED_TARGET gnutls)
# deps.sh installs pkg-config files into spikes/.deps; point pkg-config there.
set(ENV{PKG_CONFIG_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/../.deps/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(NGHTTP3 REQUIRED IMPORTED_TARGET libnghttp3)
pkg_check_modules(NGTCP2 QUIET IMPORTED_TARGET libngtcp2 libngtcp2_crypto_gnutls)

add_library(glassy_s4 STATIC src/retry_token.cpp src/cidr.cpp src/h3_codec.cpp)
target_include_directories(glassy_s4 PUBLIC src)
target_link_libraries(glassy_s4 PUBLIC PkgConfig::NGHTTP3)
target_compile_options(glassy_s4 PRIVATE -Wall -Wextra -Werror)

include(FetchContent)
# Git instead of a release tarball: the egress proxy blocks GitHub archive downloads.
FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.15.2
  GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(googletest)
enable_testing()
include(GoogleTest)

foreach(t retry_token_test cidr_test h3_codec_test)
  add_executable(${t} tests/${t}.cpp)
  target_link_libraries(${t} PRIVATE glassy_s4 GTest::gtest_main)
  target_compile_definitions(${t} PRIVATE GLASSY_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../vectors")
  gtest_discover_tests(${t})
endforeach()
