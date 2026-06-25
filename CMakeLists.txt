# Copyright (c) 2026, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

cmake_minimum_required(VERSION 3.12)
project(fhse)

enable_language(C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(FHSE_SANITIZER "Use specific sanitizer" OFF)
if(NOT FHSE_SANITIZER STREQUAL "OFF")
  if (MSVC)
    message(FATAL_ERROR "Cannot sanitize with MSVC")
  else()
    message(STATUS "Using sanitizer=${FHSE_SANITIZER}")
    add_compile_options("-fsanitize=${FHSE_SANITIZER}")
    add_link_options("-fsanitize=${FHSE_SANITIZER}")
  endif()
endif()

add_library(fhse-dependencies INTERFACE)
find_path(CBOR_INCLUDE_PATH cbor.h)
find_library(CBOR_LIBRARY cbor)
if (NOT CBOR_INCLUDE_PATH OR NOT CBOR_LIBRARY)
  message(FATAL_ERROR "Failed to find libcbor")
endif ()

set(COMPILE_GUARDS "")
option(FHSE_USE_LIBFIDO2 "Use libfido2 for fido2 key interactivity" ON)
if (FHSE_USE_LIBFIDO2)
  find_path(FIDO2_INCLUDE_PATH fido.h)
  find_library(FIDO2_LIBRARY fido2)
  if (NOT FIDO2_INCLUDE_PATH OR NOT FIDO2_LIBRARY)
    message(FATAL_ERROR "Failed to find libfido2")
  endif ()
  list(APPEND COMPILE_GUARDS "FHSE_LIBFIDO2")
endif ()

option(FHSE_USE_LIBSODIUM "Use libsodium for crypto" ON)
if (FHSE_USE_LIBSODIUM)
  find_path(SODIUM_INCLUDE_PATH sodium/core.h)
  find_library(SODIUM_LIBRARY sodium)
  if (NOT SODIUM_INCLUDE_PATH OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "Failed to find libsodium")
  endif ()
  list(APPEND COMPILE_GUARDS "FHSE_LIBSODIUM")
endif ()

target_include_directories(fhse-dependencies
  INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    ${CBOR_INCLUDE_PATH}
    ${SODIUM_INCLUDE_PATH}
    ${FIDO2_INCLUDE_PATH}
)
target_link_libraries(fhse-dependencies
  INTERFACE
    ${CBOR_LIBRARY}
    ${SODIUM_LIBRARY}
    ${FIDO2_LIBRARY}
)
target_compile_definitions(fhse-dependencies INTERFACE ${COMPILE_GUARDS})

add_subdirectory(src)
add_library(fhse)
target_include_directories(fhse PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(fhse PUBLIC fhse-public ${SODIUM_LIBRARY} PRIVATE fhse-private)

option(FHSE_TESTS "Enable FHSE tests (requires c++)" OFF)
if (FHSE_TESTS)
  enable_testing()
  enable_language(CXX)
  set(CMAKE_CXX_STANDARD 17)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  add_subdirectory(tests)
endif ()
