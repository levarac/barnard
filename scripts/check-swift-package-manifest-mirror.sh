#!/usr/bin/env bash
# Use of this source code is governed by a BSD-style license.
#
# barnard#85: the repository-root Package.swift exposes the Swift package for
# remote consumption while packages/swift/barnard/Package.swift remains the
# in-repository development manifest. This check prevents their declared
# products, targets, platforms, and Swift tools version from silently drifting.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
root_manifest="$repo_root/Package.swift"
inner_package="$repo_root/packages/swift/barnard"

if [[ ! -f "$root_manifest" ]]; then
  echo "MISSING root Swift package manifest: $root_manifest"
  exit 1
fi

root_dump="$(mktemp)"
inner_dump="$(mktemp)"
root_declarations="$(mktemp)"
inner_declarations="$(mktemp)"
trap 'rm -f "$root_dump" "$inner_dump" "$root_declarations" "$inner_declarations"' EXIT

swift package dump-package --package-path "$repo_root" >"$root_dump"
swift package dump-package --package-path "$inner_package" >"$inner_dump"

extract_declarations() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    package = json.load(source)

targets = package["targets"]
for target in targets:
    # The root manifest must point into the nested package; the inner manifest
    # uses SwiftPM's default Sources/ and Tests/ locations.
    target.pop("path", None)

declarations = {
    "platforms": package["platforms"],
    "products": package["products"],
    "targets": targets,
    "toolsVersion": package["toolsVersion"],
}
json.dump(declarations, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
}

extract_declarations "$root_dump" >"$root_declarations"
extract_declarations "$inner_dump" >"$inner_declarations"

if ! diff -u "$inner_declarations" "$root_declarations"; then
  echo "DRIFT: root and inner Swift package declarations differ."
  exit 1
fi

echo "OK: root and inner Swift package products, targets, platforms, and tools version match."
