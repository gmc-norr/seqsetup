#!/usr/bin/env bash
# Install the pinned Tailwind CSS standalone binary into .pixi/bin. The binary is
# checked against tools/tailwind-sha256.txt before it is made executable, and this
# script never runs it (`--version` in Tailwind v4 also prints a whole stylesheet).
# Run from the repo root (pixi run tailwind-install).
set -euo pipefail

VERSION=$(cat tools/tailwind-version.txt)
DEST=.pixi/bin/tailwindcss
SUMS=tools/tailwind-sha256.txt

case "$(uname -sm)" in
  "Linux x86_64")  PLATFORM="linux-x64" ;;
  "Linux aarch64") PLATFORM="linux-arm64" ;;
  "Darwin x86_64") PLATFORM="macos-x64" ;;
  "Darwin arm64")  PLATFORM="macos-arm64" ;;
  *) echo "Unsupported platform: $(uname -sm)" >&2; exit 1 ;;
esac
NAME="tailwindcss-$PLATFORM"

IFS= read -r PINNED < "$SUMS" || true
if [ "$PINNED" != "# tailwindcss $VERSION" ]; then
  echo "$SUMS pins ${PINNED#\# }, not $VERSION (tools/tailwind-version.txt)." >&2
  echo "Copy the new release's values from its sha256sums.txt into $SUMS" >&2
  echo "and change its first line." >&2
  exit 1
fi

# A name is read as written in the release's sha256sums.txt (./tailwindcss-...) or without
# the leading ./.
PIN='!/^#/ && ($2 == name || $2 == "./" name)'
COUNT=$(awk -v name="$NAME" "$PIN { n++ } END { print n + 0 }" "$SUMS")
if [ "$COUNT" != 1 ]; then
  echo "$SUMS has no single SHA-256 for $NAME." >&2
  exit 1
fi
EXPECTED=$(awk -v name="$NAME" "$PIN { print \$1 }" "$SUMS")

if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | awk '{ print $1 }'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | awk '{ print $1 }'; }
else
  echo "Neither sha256sum nor shasum is installed, so the Tailwind binary cannot be checked." >&2
  exit 1
fi

# A binary already installed is hashed, never run, before it is trusted.
if [ -e "$DEST" ] && [ ! -f "$DEST" ]; then
  echo "$DEST is not a file. Remove it and run the install again." >&2
  exit 1
fi
if [ -f "$DEST" ]; then
  INSTALLED=$(sha256_of "$DEST")
  if [ "$INSTALLED" = "$EXPECTED" ]; then
    [ -x "$DEST" ] || chmod 755 "$DEST"
    echo "Tailwind $VERSION already installed at $DEST"
    exit 0
  fi
  echo "$DEST does not match the pinned SHA-256; removed, installing again."
  rm -f "$DEST"
fi

# Each run fills its own staging file (mode 600, so not executable), in the same
# folder so that installing it is one rename. Any exit before that removes it.
mkdir -p .pixi/bin
STAGING=$(mktemp .pixi/bin/tailwindcss.XXXXXX)
trap 'rm -f "$STAGING"' EXIT

if [ -f "tools/vendor/$NAME" ]; then
  SOURCE="tools/vendor/$NAME"
  echo "Using the vendored binary at $SOURCE"
  cat "$SOURCE" > "$STAGING"
else
  SOURCE="https://github.com/tailwindlabs/tailwindcss/releases/download/$VERSION/$NAME"
  echo "Downloading $SOURCE"
  curl -fsSL -o "$STAGING" "$SOURCE"
fi

ACTUAL=$(sha256_of "$STAGING")
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "$NAME from $SOURCE has SHA-256" >&2
  echo "$ACTUAL, not the $EXPECTED that $SUMS pins. It was not installed." >&2
  echo "If you changed tools/tailwind-version.txt, copy the new release's values from its" >&2
  echo "sha256sums.txt into $SUMS." >&2
  exit 1
fi

chmod 755 "$STAGING"
mv -f "$STAGING" "$DEST"
echo "Installed Tailwind $VERSION at $DEST"
