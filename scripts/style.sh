#!/bin/bash

set -euo pipefail

msg() {
    echo -e "[+] ${1-}" >&2
}

hurt() {
    echo -e "[-] ${1-}" >&2
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

usage() {
    cat <<EOF
[!] Usage: $(basename "${BASH_SOURCE[0]}") [options]

    Options:
    -h, --help          Print this message and exit
    -f, --overwrite     Overwrite the original source files
EOF
}

parse_params() {
    while :; do
        case "${1-}" in
        -h | --help) usage; exit ;;
        -f | --overwrite)
            OVERWRITE=1
            ;;
        -?*) die "Unknown option: $1\n$(usage)" ;;
        *) break ;;
        esac
        shift
    done
}

main() {
    OVERWRITE=0
    parse_params "$@"

    if command -v yapf3 >/dev/null 2>&1; then
        YAPF=yapf3
    else
        YAPF=yapf
    fi

    check_depends clang-format "$YAPF"

    SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    SRC_DIR="$(realpath "$SCRIPT_DIR/../src")"

    if [ $OVERWRITE -eq 0 ]; then
        # C++: clang-format
        find "$SRC_DIR" -type f -regex '.*\.\(c\|h\|cpp\|hpp\)' \
            -exec clang-format --Werror --dry-run {} +
        # Python: yapf
        $YAPF -p -r -d "$SRC_DIR"
        msg "Coding style is compliant"
    else
        # C++: clang-format
        find "$SRC_DIR" -type f -regex '.*\.\(c\|h\|cpp\|hpp\)' \
            -exec clang-format --Werror -i {} +
        # Python: yapf
        $YAPF -p -r -i "$SRC_DIR"
    fi
}


main "$@"

# vim: set ts=4 sw=4 et:
