#!/usr/bin/env bash
# Use of this source code is governed by the MIT license in /LICENSE.
#
# Regenerates the Flutter plugin's referencing mirror copies from the canonical
# native Swift and Android packages.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
# shellcheck source=scripts/mirror-manifest.sh
source "$script_dir/mirror-manifest.sh"

swift_origin_dir="$repo_root/packages/swift/barnard/Sources"
swift_mirror_dir="$repo_root/packages/dart/barnard/ios/barnard/Sources/barnard"
android_origin_dir="$repo_root/packages/android/barnard/src/main/kotlin/org/levarac/barnard"
android_mirror_dir="$repo_root/packages/dart/barnard/android/src/main/kotlin/org/levarac/barnard"

require_origin() {
  local origin_file="$1"
  if [[ ! -f "$origin_file" ]]; then
    echo "MISSING native origin: $origin_file" >&2
    return 1
  fi
}

# Validate the complete source set before copying so a missing later origin
# cannot leave the Dart mirrors partially synchronized.
for pair in "${swift_mirrored_pairs[@]}"; do
  require_origin "$swift_origin_dir/${pair%%|*}"
done
for relative_path in "${android_mirrored_files[@]}"; do
  require_origin "$android_origin_dir/$relative_path"
done

synced_count=0

sync_file() {
  local origin_file="$1"
  local mirror_file="$2"

  if cmp -s "$origin_file" "$mirror_file"; then
    return
  fi

  mkdir -p "$(dirname "$mirror_file")"
  cp "$origin_file" "$mirror_file"
  echo "SYNCED: $origin_file -> $mirror_file"
  synced_count=$((synced_count + 1))
}

for pair in "${swift_mirrored_pairs[@]}"; do
  origin_relative="${pair%%|*}"
  mirror_relative="${pair#*|}"
  sync_file \
    "$swift_origin_dir/$origin_relative" \
    "$swift_mirror_dir/$mirror_relative"
done

for relative_path in "${android_mirrored_files[@]}"; do
  sync_file \
    "$android_origin_dir/$relative_path" \
    "$android_mirror_dir/$relative_path"
done

if [[ $synced_count -eq 0 ]]; then
  echo "OK: Dart mirrors already match their native origins."
else
  echo "OK: synchronized $synced_count Dart mirror file(s) from native origins."
fi
