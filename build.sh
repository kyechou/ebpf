#!/bin/bash

set -euo pipefail

msg() {
    echo -e "[+] ${1-}" >&2
}

die() {
    echo -e "[!] ${1-}" >&2
    exit 1
}

check_depends() {
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            die "'$cmd' not found"
        fi
    done
}

usage()
{
    cat <<EOF
[!] Usage: $(basename "${BASH_SOURCE[0]}") [options]

    Options:
    -h, --help          Print this message and exit
    -d, --debug         Enable debugging
    -c, --clean         Clean all build files
    -r, --rebuild       Reconfigure and rebuild everything
EOF
}

parse_params() {
    DEBUG=0
    CLEAN=0
    REBUILD=0

    while :; do
        case "${1-}" in
        -h | --help) usage; exit ;;
        -d | --debug)
            DEBUG=1 ;;
        -c | --clean)
            CLEAN=1 ;;
        -r | --rebuild)
            REBUILD=1 ;;
        -?*) die "Unknown option: $1\n$(usage)" ;;
        *) break ;;
        esac
        shift
    done
}

main() {
    MAKEFLAGS="-j$(nproc)"
    CMAKE_ARGS=()
    parse_params "$@"
    check_depends cmake
    export MAKEFLAGS

    SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    PROJECT_DIR="$(realpath "${SCRIPT_DIR}")"
    BUILD_DIR="$(realpath "${PROJECT_DIR}"/build)"

    cd "${PROJECT_DIR}"
    git submodule update --init --recursive

    if [ $REBUILD -ne 0 ] || [ $CLEAN -ne 0 ]; then
        # clean up old builds
        git submodule foreach --recursive git clean -xdf
        rm -rf "${BUILD_DIR}"

        if [ $CLEAN -ne 0 ]; then
            return
        fi
    fi

    if [ $DEBUG -ne 0 ]; then
        CMAKE_ARGS+=('-DCMAKE_BUILD_TYPE=Debug')
    else
        CMAKE_ARGS+=('-DCMAKE_BUILD_TYPE=Release')
    fi

    # configure and build
    cmake -B "${BUILD_DIR}" -S "${PROJECT_DIR}" "${CMAKE_ARGS[@]}"
    cmake --build "${BUILD_DIR}"
}


main "$@"

# vim: set ts=4 sw=4 et:
