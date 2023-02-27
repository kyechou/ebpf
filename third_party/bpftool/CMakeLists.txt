ExternalProject_Add(bpftool
    PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/bpftool
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
)

set(bpftool_VERSION "7.1.0")
set(bpftool_EXECUTABLE ${CMAKE_CURRENT_BINARY_DIR}/bpftool)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(bpftool
    FOUND_VAR bpftool_FOUND
    REQUIRED_VARS bpftool_EXECUTABLE
    VERSION_VAR bpftool_VERSION)

if(bpftool_FOUND AND NOT TARGET bpftool::bpftool)
    add_executable(bpftool::bpftool IMPORTED)
    set_target_properties(bpftool::bpftool PROPERTIES IMPORTED_LOCATION "${bpftool_EXECUTABLE}")
endif()
