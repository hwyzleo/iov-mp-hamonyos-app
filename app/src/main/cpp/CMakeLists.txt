# the minimum version of CMake.
cmake_minimum_required(VERSION 3.5.0)
project(iov-mp-hamonyos-app)

set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

if(DEFINED PACKAGE_FIND_FILE)
    include(${PACKAGE_FIND_FILE})
endif()

include_directories(${NATIVERENDER_ROOT_PATH}
                    ${NATIVERENDER_ROOT_PATH}/include)

add_library(openssl INTERFACE IMPORTED)

find_package(openssl REQUIRED)

target_include_directories(openssl INTERFACE ${NATIVERENDER_ROOT_PATH}/../../../../../../../open/ohos-openssl/prelude/arm64-v8a/include)
target_link_directories(openssl INTERFACE ${NATIVERENDER_ROOT_PATH}/../../../../../../../open/ohos-openssl/prelude/arm64-v8a/lib)

add_library(app SHARED napi_init.cpp)
target_link_libraries(app PUBLIC libace_napi.z.so openssl crypto ssl)