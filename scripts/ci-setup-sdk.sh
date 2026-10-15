#!/usr/bin/env bash
# Installs the pinned Android SDK into $ANDROID_HOME (default: $CI_PROJECT_DIR/android-sdk).
# Idempotent and cache-friendly: once the SDK is present, re-runs are a no-op.
#
# Used by .gitlab-ci.yml. Also runnable locally if you want a clean, versioned SDK:
#   ANDROID_HOME=/tmp/sdk SDK_PLATFORM=36 SDK_BUILD_TOOLS=36.0.0 bash scripts/ci-setup-sdk.sh
set -euo pipefail

SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -z "$SDK_ROOT" ]; then
  echo "ERROR: ANDROID_HOME or ANDROID_SDK_ROOT must be set" >&2
  exit 1
fi

CMDLINE_TOOLS_VERSION="${CMDLINE_TOOLS_VERSION:-11076708}"
# SHA-256 of commandlinetools-linux-11076708_latest.zip. Computed from a download whose
# SHA-1 matched Google's own repository2-3.xml (d313adb7aedccf6cf0cfca51ec180f0059f5f8f8).
# A tampered or truncated zip must stop the build, not become the toolchain. Bumping
# CMDLINE_TOOLS_VERSION means re-deriving this the same way.
CMDLINE_TOOLS_SHA256="${CMDLINE_TOOLS_SHA256:-2d2d50857e4eb553af5a6dc3ad507a17adf43d115264b1afc116f95c92e5e258}"
SDK_PLATFORM="${SDK_PLATFORM:-36}"
SDK_BUILD_TOOLS="${SDK_BUILD_TOOLS:-36.0.0}"

# The eclipse-temurin base image ships apt but not curl/unzip; install them once.
if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
  if [ "$(id -u)" = "0" ]; then
    apt-get update -qq && apt-get install -y -qq curl unzip >/dev/null
  else
    echo "ERROR: curl/unzip missing and not running as root" >&2
    exit 1
  fi
fi

if [ ! -x "$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" ]; then
  mkdir -p "$SDK_ROOT/cmdline-tools"
  zip=$(mktemp --suffix=.zip)
  trap 'rm -f "$zip"' EXIT
  curl -fsSL "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip" \
    -o "$zip"
  echo "${CMDLINE_TOOLS_SHA256}  $zip" | sha256sum -c --quiet - || {
    echo "ERROR: cmdline-tools checksum mismatch" >&2
    exit 1
  }
  unzip -q -o "$zip" -d "$SDK_ROOT/cmdline-tools"
  mv "$SDK_ROOT/cmdline-tools/cmdline-tools" "$SDK_ROOT/cmdline-tools/latest"
fi

SDKMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"

# Accept licenses non-interactively (may already be accepted — don't fail on that).
yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true

"$SDKMANAGER" --install \
  "platform-tools" \
  "platforms;android-${SDK_PLATFORM}" \
  "build-tools;${SDK_BUILD_TOOLS}" >/dev/null

echo "Android SDK ready at $SDK_ROOT (platform ${SDK_PLATFORM}, build-tools ${SDK_BUILD_TOOLS})"
