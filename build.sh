#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")"
RT="$(pwd)"

LIBPROXY_PKG="./proxy/libproxy"
LIBPROXY_OUT="proxy/libproxy/libproxy.a"
DEFAULT_INSTALL_DIR="" #"/mnt/shared/heroic/games/rocketleague"

meson_setup_flags=()
go_build_flags=()

opt_dist=0
opt_clean=0
opt_release=0
opt_install=""
opt_install_dir="$DEFAULT_INSTALL_DIR"
while [[ $# -gt 0 ]]; do
    case "$1" in
        '--dist')
            opt_dist=1
            ;;
        '-c' | '--clean')
            opt_clean=1
            ;;
        '--release')
            opt_release=1
            set -- "$@" --flag logfile
            ;;
        '-i' | '--install')
            opt_install=1
            ;;
        '-id' | '--install-dir')
            if [[ $# -ge 2 ]]; then
                opt_install_dir="$2"
                shift
            else
                opt_install_dir="$DEFAULT_INSTALL_DIR"
            fi
            ;;
        '-f' | '--flag')
            meson_setup_flags+=("-D${2}=true")
            shift
            ;;
        *)
            echo -e "error: unknown argument \"$1\"\n"
            exit 1
            ;;
    esac

    shift
done

BUILD_DIR=build
if [[ $opt_release -eq 1 ]]; then
    BUILD_DIR=build-release

    meson_setup_flags+=(-Dbuildtype=release)
    go_build_flags+=(-ldflags "-s -w")
else
    meson_setup_flags+=(-Dbuildtype=debug)
fi

set -x

if [[ $opt_dist == 1 ]]; then
    GIT_INFO="$(git log -1 --date=format:"%Y-%m-%d" --format="%h_%ad")"

    rm -rf dist
    mkdir -p dist

    ./build.sh --clean -f dump_aes_decrypt
    ./build.sh --clean --release

    cd "$RT/build"
    tar -cvJf "$RT/dist/ioannes-debug_$GIT_INFO.tar.xz" \
        *.dll \
        -C "$RT" LICENSE THIRDPARTY

    cd "$RT/build-release"
    tar -cvJf "$RT/dist/ioannes_$GIT_INFO.tar.xz" \
        *.dll \
        -C "$RT" LICENSE THIRDPARTY

    exit 0
fi

if [[ $opt_clean -eq 1 ]]; then
    rm -rf "$BUILD_DIR"
    rm -f "$LIBPROXY_OUT"
fi
if [[ $opt_release -eq 1 ]]; then
    rm -f "$LIBPROXY_OUT"
fi

if [[ ! -f "$LIBPROXY_OUT" ]] || [[ "$(find "proxy" -type f -newer "$LIBPROXY_OUT" | wc -l)" -gt 0 ]]; then
    # Also generates libproxy.h, so weird how it's not a flag but whatever
    GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 \
        go build -v "${go_build_flags[@]}" -buildmode c-archive -o "$LIBPROXY_OUT" "$LIBPROXY_PKG"
fi

if [[ ! -d "$BUILD_DIR" ]]; then
    meson setup "$BUILD_DIR" --cross-file mingw.cross "${meson_setup_flags[@]}"
fi

meson compile -C "$BUILD_DIR"
if [[ $opt_release -eq 1 ]]; then
    x86_64-w64-mingw32-strip "$BUILD_DIR"/*.dll
    upx --best -9 "$BUILD_DIR"/*.dll
fi

if [[ $opt_install -eq 1 ]]; then
    cp -f "$BUILD_DIR/ioannes.dll" "$opt_install_dir"/Binaries/Win64/version.dll
fi
