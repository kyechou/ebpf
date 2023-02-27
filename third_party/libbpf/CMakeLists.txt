ExternalProject_Add(libbpf
    PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/libbpf
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make
        BUILD_STATIC_ONLY=1
        OBJDIR=${CMAKE_CURRENT_BINARY_DIR}
        DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/install
        INCLUDEDIR=
        UAPIDIR=
        LIBDIR=
        install install_uapi_headers
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
)

set(libbpf_VERSION "1.1.0")
set(libbpf_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/install)
set(libbpf_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/install/libbpf.a)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libbpf
    FOUND_VAR libbpf_FOUND
    REQUIRED_VARS libbpf_INCLUDE_DIRS libbpf_LIBRARIES
    VERSION_VAR libbpf_VERSION)

if(libbpf_FOUND AND NOT TARGET libbpf::libbpf)
    add_library(libbpf::libbpf UNKNOWN IMPORTED)
    target_include_directories(libbpf::libbpf SYSTEM INTERFACE "${libbpf_INCLUDE_DIRS}")
    target_link_libraries(libbpf::libbpf INTERFACE "${libbpf_LIBRARIES}")
    set_target_properties(libbpf::libbpf PROPERTIES IMPORTED_LOCATION "${libbpf_LIBRARIES}")
endif()
