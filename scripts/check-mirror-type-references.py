#!/usr/bin/env python3
# Use of this source code is governed by the MIT license in /LICENSE.
"""Compiler-free, conservative project-type check for the Dart native mirrors.

Source mirror-manifest.sh with Bash; never infer mirrored files by basename.
Inventory named Swift class/struct/enum/protocol/actor/typealias and Kotlin/Java
class/interface/object/typealias/enum/record declarations in production sources.
Require each known project identifier used by a manifested source to have a
declaration anywhere in that Dart target (independent implementations count).
Comments are ignored. String identifiers remain possible references, including
interpolation, but strings cannot define types: prefer a named false failure.

This does NOT prove compilation: no scope/qualified-name/visibility resolution,
extension-member checking, typealias expansion, generic substitution, dependency
resolution, generated types, conditional-compilation or target-exclusion parsing.
Same-spelled types can hide missing qualified types; shadowing, inactive branches,
strings and cross-package names can cause false failures. Only ASCII identifiers
and conventional declarations are recognized. Update the inventory paths if the
target layouts change. Existing byte checks and native CI remain necessary.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path


IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
STRING_START = re.compile(r'(#+)?("""|"|\')')
DECLARATIONS = {
    "swift": {"class", "struct", "enum", "protocol", "actor", "typealias"},
    "android": {"class", "interface", "object", "typealias", "enum", "record"},
}
# Swift's class func/var and Kotlin's enum class are not names.
NON_NAMES = {"class", "interface", "func", "var", "let", "subscript"}


def lexical_views(text):
    """Return code and conservative references, preserving offsets and newlines."""
    code = list(text)
    references = list(text)

    def erase(view, start, end):
        view[start:end] = ["\n" if c == "\n" else " " for c in text[start:end]]

    def comment_end(start):
        if text.startswith("//", start):
            end = text.find("\n", start)
            return len(text) if end < 0 else end
        depth, pos = 1, start + 2
        while pos < len(text) and depth:
            if text.startswith("/*", pos):
                depth += 1
                pos += 2
            elif text.startswith("*/", pos):
                depth -= 1
                pos += 2
            else:
                pos += 1
        return pos

    def interpolation_end(pos, opening):
        closing = ")" if opening == "(" else "}"
        depth = 1
        while pos < len(text) and depth:
            match = STRING_START.match(text, pos)
            if text.startswith(("//", "/*"), pos):
                end = comment_end(pos)
                erase(references, pos, end)
                pos = end
            elif match:
                pos = string_end(match)
            elif text[pos] == opening:
                depth += 1
                pos += 1
            elif text[pos] == closing:
                depth -= 1
                pos += 1
            else:
                pos += 1
        return pos

    def string_end(match):
        hashes, quote = match.group(1) or "", match.group(2)
        pos = match.end()
        delimiter = quote + hashes
        swift_interpolation = "\\" + hashes + "("
        while pos < len(text):
            if text.startswith(delimiter, pos):
                return pos + len(delimiter)
            if text.startswith(swift_interpolation, pos):
                pos = interpolation_end(pos + len(swift_interpolation), "(")
            elif text.startswith("${", pos):
                pos = interpolation_end(pos + 2, "{")
            elif text[pos] == "\\" and not hashes and quote != '"""':
                pos += 2
            else:
                pos += 1
        return pos

    pos = 0
    while pos < len(text):
        match = STRING_START.match(text, pos)
        if text.startswith(("//", "/*"), pos):
            end = comment_end(pos)
            erase(code, pos, end)
            erase(references, pos, end)
            pos = end
        elif match:
            end = string_end(match)
            erase(code, pos, end)
            pos = end
        else:
            pos += 1
    return "".join(code), "".join(references)


def declarations(code, language):
    # Preserve punctuation so `object : Interface` cannot declare Interface.
    tokens = re.findall(r"[A-Za-z_][A-Za-z_0-9]*|[^\s]", code)
    return {
        tokens[i + 1]
        for i, token in enumerate(tokens[:-1])
        if token in DECLARATIONS[language]
        and IDENTIFIER.fullmatch(tokens[i + 1])
        and tokens[i + 1] not in NON_NAMES
    }


def manifest_paths(root, language):
    variable = "swift_mirrored_pairs" if language == "swift" else "android_mirrored_files"
    result = subprocess.run(
        ["bash", "-eu", "-c", 'source "$1"; printf "%s\\0" "${' + variable + '[@]}"',
         "mirror-manifest", str(root / "scripts/mirror-manifest.sh")],
        check=True, capture_output=True,
    )
    entries = result.stdout.decode("utf-8").rstrip("\0").split("\0")
    if not entries or any(not entry for entry in entries):
        raise ValueError(f"empty {variable} in mirror-manifest.sh")
    return [entry.split("|", 1) if language == "swift" else (entry, entry)
            for entry in entries]


def check(root, language):
    if language == "swift":
        origin = root / "packages/swift/barnard/Sources"
        mirror = root / "packages/dart/barnard/ios/barnard/Sources/barnard"
        suffixes = {".swift"}
    else:
        origin = root / "packages/android/barnard/src/main"
        mirror = root / "packages/dart/barnard/android/src/main"
        suffixes = {".kt", ".java"}

    def source_views(path):
        text = path.read_text(encoding="utf-8")
        if language == "swift" and "#/" in text:
            # Fail before comment erasure can hide references or declarations.
            raise ValueError(f"unsupported Swift extended regex (#/) in source: {path}")
        return lexical_views(text)

    def inventory(directory):
        if not directory.is_dir():
            raise ValueError(f"missing production source directory: {directory}")
        result = {}
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path.suffix in suffixes:
                code, _ = source_views(path)
                for name in declarations(code, language):
                    result.setdefault(name, []).append(path.relative_to(root))
        return result

    native_types = inventory(origin)
    mirror_types = inventory(mirror)
    missing = native_types.keys() - mirror_types.keys()
    paths = manifest_paths(root, language)
    status, checked, failures = 0, 0, 0
    for relative, mirror_relative in paths:
        path = origin / relative if language == "swift" else origin / "kotlin/org/levarac/barnard" / relative
        if not path.is_file():
            raise ValueError(f"missing manifested native source: {path}")
        mirror_path = mirror / mirror_relative if language == "swift" else mirror / "kotlin/org/levarac/barnard" / mirror_relative
        if not mirror_path.is_file():
            raise ValueError(f"missing manifested mirror source: {mirror_path}")
        if path.suffix not in suffixes:
            continue  # e.g. PrivacyInfo.xcprivacy is a byte-mirrored resource.
        checked += 1
        _, references = source_views(path)
        reported = set()
        for match in IDENTIFIER.finditer(references):
            name = match.group()
            if name in missing and name not in reported:
                line = references.count("\n", 0, match.start()) + 1
                print(f"MISSING project type {name}: {path.relative_to(root)}:{line}")
                print("  native declaration: " + ", ".join(map(str, native_types[name])))
                print(f"  no declaration in mirror target: {mirror.relative_to(root)}")
                reported.add(name)
                failures += 1
                status = 1
    print(f"{'FAIL' if status else 'OK'}: {language} mirror type references: "
          f"{checked} files, {len(native_types)} native types, "
          f"{len(mirror_types)} mirror types, {failures} missing references.")
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("language", choices=("swift", "android"))
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        return check(args.repo_root.resolve(), args.language)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
