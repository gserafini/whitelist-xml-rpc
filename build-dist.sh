#!/bin/bash
#
# Build distribution zip for WordPress.org submission
# Excludes development files per .distignore
#

set -e

PLUGIN_SLUG="whitelist-xml-rpc"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="/tmp/${PLUGIN_SLUG}-build"
DIST_DIR="${SCRIPT_DIR}/dist"

# Get version from main plugin file
VERSION=$(grep -o "Version: [0-9.]*" "${SCRIPT_DIR}/${PLUGIN_SLUG}.php" | cut -d' ' -f2)

if [ -z "$VERSION" ]; then
    echo "Error: Could not determine version from plugin file"
    exit 1
fi

echo "Building ${PLUGIN_SLUG} v${VERSION}..."

# Clean up any previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/${PLUGIN_SLUG}"
mkdir -p "$DIST_DIR"

# Build exclude pattern from .distignore
EXCLUDE_ARGS=""
if [ -f "${SCRIPT_DIR}/.distignore" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "$line" ]] && continue
        EXCLUDE_ARGS="$EXCLUDE_ARGS --exclude=$line"
    done < "${SCRIPT_DIR}/.distignore"
fi

# Also exclude this build script and dist directory
EXCLUDE_ARGS="$EXCLUDE_ARGS --exclude=build-dist.sh --exclude=dist"

# Copy files to build directory
rsync -av $EXCLUDE_ARGS "${SCRIPT_DIR}/" "$BUILD_DIR/${PLUGIN_SLUG}/"

# Create zip
OUTPUT_FILE="${DIST_DIR}/${PLUGIN_SLUG}-${VERSION}.zip"
rm -f "$OUTPUT_FILE"
cd "$BUILD_DIR"
zip -r "$OUTPUT_FILE" "${PLUGIN_SLUG}"

# Clean up
rm -rf "$BUILD_DIR"

# Show results
echo ""
echo "✓ Built: ${OUTPUT_FILE}"
echo ""
echo "Contents:"
unzip -l "$OUTPUT_FILE" | head -30
echo ""
echo "File size: $(du -h "$OUTPUT_FILE" | cut -f1)"
echo ""
echo "Ready for WordPress.org submission!"
