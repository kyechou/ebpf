cmake_minimum_required(VERSION 3.16)
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
project(ebpf VERSION 0.1 HOMEPAGE_URL https://github.com/kyechou/ebpf LANGUAGES C CXX)
include(ExternalProject)

#
# compile options
#
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror -O2)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Wno-c99-designator)
endif()

#
# release/debug compile options
#
set(CMAKE_C_FLAGS_RELEASE "-O3")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-g -O3")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-g -O3")
set(CMAKE_C_FLAGS_DEBUG "-g -fsanitize=address -fno-omit-frame-pointer -fno-common")
set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address -fno-omit-frame-pointer -fno-common")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address")
if ("${CMAKE_BUILD_TYPE}" STREQUAL "")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

#
# third party libraries
#
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
add_subdirectory(third_party/libbpf)
add_subdirectory(third_party/bpftool)
find_package(BpfObject REQUIRED)

#
# source directory and files
#
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
FILE(GLOB_RECURSE BPF_SRC_FILES CONFIGURE_DEPENDS ${SRC_DIR}/*.bpf.c)

#
# executable target for each bpf application
#
foreach(BPF_SRC_FILE ${BPF_SRC_FILES})
    get_filename_component(BPF_STEM ${BPF_SRC_FILE} NAME_WE)
    bpf_object(${BPF_STEM} ${BPF_STEM}.bpf.c)
    add_executable(${BPF_STEM} ${SRC_DIR}/${BPF_STEM}.cpp)
    target_link_libraries(${BPF_STEM} PRIVATE ${BPF_STEM}_skel)
endforeach()
