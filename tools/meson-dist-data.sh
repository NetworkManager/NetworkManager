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

if [ "$MESON_BUILD_ROOT" = "" ]; then
    if [ "$1" = "--build-root" ]; then
        MESON_BUILD_ROOT="$2"
    fi
fi

ensure_var_path "MESON_DIST_ROOT"
ensure_var_path "MESON_BUILD_ROOT"

MAX_JOBS_ARG=
if [[ "$MAX_JOBS" != "" ]]; then
    MAX_JOBS_ARG="-j$MAX_JOBS"
fi

ninja -C "$MESON_BUILD_ROOT" $MAX_JOBS_ARG all libnm-doc NetworkManager-doc

cp -Tr "$MESON_BUILD_ROOT/docs/api/html" "$MESON_DIST_ROOT/docs/api/html"
cp -Tr "$MESON_BUILD_ROOT/docs/libnm/html" "$MESON_DIST_ROOT/docs/libnm/html"
cp "$MESON_BUILD_ROOT/man/"*.[1-8] "$MESON_DIST_ROOT/man"
