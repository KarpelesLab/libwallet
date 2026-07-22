#!/usr/bin/env bash
# Export libwallet build-version metadata into $GITHUB_ENV so the Rust build
# bakes it into the FFI lib via option_env! (handlers/info.rs). Mirrors the old
# Go -ldflags -X wltbase.{dateTag,gitTag,version} injection.
#
# LIBWALLET_VERSION is empty unless the workflow was triggered by a `v*` tag —
# handlers/info.rs reads it as the "release vs dev" signal exposed by
# Info:version for runtime mismatch detection.
set -euo pipefail

{
  echo "LIBWALLET_GIT_TAG=$(git rev-parse --short HEAD)"
  echo "LIBWALLET_DATE_TAG=$(TZ=UTC git show -s --format=%cd --date=format-local:%Y%m%d%H%M%S HEAD)"
  if [[ "${GITHUB_REF:-}" == refs/tags/v* ]]; then
    echo "LIBWALLET_VERSION=${GITHUB_REF_NAME#v}"
  else
    echo "LIBWALLET_VERSION="
  fi
} >> "$GITHUB_ENV"
