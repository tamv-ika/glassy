cmake_minimum_required(VERSION 3.28)
project(s2_webrtc_server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GNUTLS REQUIRED IMPORTED_TARGET gnutls)
# The server needs libdatachannel (built by deps.sh); the ice_pwd tests only need GnuTLS.
find_package(LibDataChannel CONFIG QUIET)

add_library(glassy_ice STATIC src/ice_pwd.cpp)
target_include_directories(glassy_ice PUBLIC src)
target_link_libraries(glassy_ice PUBLIC PkgConfig::GNUTLS)
target_compile_options(glassy_ice PRIVATE -Wall -Wextra -Werror)

if(LibDataChannel_FOUND)
  add_executable(s2-webrtc-server src/main.cpp)
  target_link_libraries(s2-webrtc-server PRIVATE glassy_ice LibDataChannel::LibDataChannel)
  target_compile_options(s2-webrtc-server PRIVATE -Wall -Wextra -Werror)
else()
  message(WARNING "LibDataChannel not found; run ./deps.sh to build s2-webrtc-server")
endif()

include(FetchContent)
# Git instead of a release tarball: the egress proxy blocks GitHub archive downloads.
FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.15.2
  GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(googletest)
enable_testing()

add_executable(ice_pwd_test tests/ice_pwd_test.cpp)
target_link_libraries(ice_pwd_test PRIVATE glassy_ice GTest::gtest_main)
# Absolute path so the test does not depend on the working directory ctest uses.
target_compile_definitions(ice_pwd_test PRIVATE
  GLASSY_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../vectors")
include(GoogleTest)
gtest_discover_tests(ice_pwd_test)
