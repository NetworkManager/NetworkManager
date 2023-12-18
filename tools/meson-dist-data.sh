#!/bin/bash
set -e

ensure_var_path() {
  if [ "${!1}" = "" ]; then
      echo "$0: Required variable $1 is not set, aborting" >&2
      exit 1
  fi

  if [ ! -d "${!1}" ]; then
      echo "$0: Path '${!1}' in $1 does not exist or is not directory, aborting" >&2
      exit 1
  fi
}

copy_from_build() {
    cp -Tr "$MESON_BUILD_ROOT/$1" "$MESON_DIST_ROOT/$1"
}

if [ "$MESON_BUILD_ROOT" = "" ]; then
    if [ "$1" = "--build-root" ]; then
        MESON_BUILD_ROOT="$2"
    fi
fi

ensure_var_path "MESON_DIST_ROOT"
ensure_var_path "MESON_BUILD_ROOT"
ensure_var_path "MESON_SOURCE_ROOT"

ninja -C "$MESON_BUILD_ROOT" all libnm-doc NetworkManager-doc

mkdir -p "$MESON_DIST_ROOT/docs/"
copy_from_build /docs/api/
copy_from_build /docs/libnm/
copy_from_build /man/
