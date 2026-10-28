#!/usr/bin/env python3
"""Compiler-free mirror fixtures; run with unittest discovery from the repo root."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class MirrorFixtures:
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.write("scripts/mirror-manifest.sh", self.manifest)
        for name in (
            f"check-{self.language}-mirror.sh",
            "check-mirror-type-references.py",
        ):
            source = ROOT / "scripts" / name
            if source.exists():
                shutil.copyfile(source, self.root / "scripts" / name)
        self.write(self.origin / self.source_file, self.shared_source)
        self.write(self.mirror / self.mirror_file, self.shared_source)

    def write(self, path, content):
        path = self.root / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def check(self):
        return subprocess.run(
            ["bash", str(self.root / "scripts" / f"check-{self.language}-mirror.sh")],
            text=True, capture_output=True,
        )

    def reference(self, source):
        self.write(self.origin / self.source_file, source)
        self.write(self.mirror / self.mirror_file, source)

    def test_native_only_type_fails_with_type_and_file(self):
        self.write(self.origin / ("NativeOnly" + self.suffix), self.missing_declaration)
        self.reference(self.missing_reference)
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("NativeOnly", result.stdout)
        self.assertIn(str(self.origin / self.source_file), result.stdout)

    def test_independently_defined_type_in_both_trees_passes(self):
        self.write(self.origin / ("NativeOnly" + self.suffix), self.missing_declaration)
        self.write(self.mirror / ("Independent" + self.suffix), self.missing_declaration)
        self.reference(self.missing_reference)
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_manifested_type_passes(self):
        self.reference(self.missing_declaration + "\n" + self.missing_reference)
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_standard_library_and_platform_types_pass(self):
        self.reference(self.platform_source)
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_comments_are_not_references_or_definitions(self):
        self.write(self.origin / ("NativeOnly" + self.suffix), self.missing_declaration)
        self.reference("/* outer /* nested */ NativeOnly */\n// NativeOnly\n" + self.shared_source)
        self.assertEqual(self.check().returncode, 0)
        self.reference(self.missing_reference)
        self.write(self.mirror / ("Comment" + self.suffix), "/* " + self.missing_declaration + " */")
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_string_interpolation_keeps_type_references(self):
        self.write(self.origin / ("NativeOnly" + self.suffix), self.missing_declaration)
        self.reference(self.interpolated_reference)
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("NativeOnly", result.stdout)

    def test_string_cannot_supply_a_type_definition(self):
        self.write(self.origin / ("NativeOnly" + self.suffix), self.missing_declaration)
        self.reference(self.missing_reference)
        self.write(self.mirror / ("String" + self.suffix), 'let text = "class NativeOnly {}"\n')
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_string_mentions_conservatively_fail(self):
        self.write(self.origin / ("NativeOnly" + self.suffix), self.missing_declaration)
        self.reference('var text = "NativeOnly"\n')
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("NativeOnly", result.stdout)

    def test_generic_argument_reference_fails(self):
        self.write(self.origin / ("NativeOnly" + self.suffix), self.missing_declaration)
        self.reference("var value: Array<NativeOnly>\n")
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("NativeOnly", result.stdout)

    def test_missing_manifested_file_fails(self):
        (self.root / self.mirror / self.mirror_file).unlink()
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("MISSING", result.stdout)


class SwiftMirrorFixtures(MirrorFixtures, unittest.TestCase):
    language = "swift"
    suffix = ".swift"
    origin = Path("packages/swift/barnard/Sources")
    mirror = Path("packages/dart/barnard/ios/barnard/Sources/barnard")
    source_file = Path("Barnard/Shared.swift")
    mirror_file = Path("Shared.swift")
    manifest = 'swift_mirrored_pairs=("Barnard/Shared.swift|Shared.swift")\n'
    shared_source = "struct Shared {}\n"
    missing_declaration = "struct NativeOnly {}\n"
    missing_reference = "struct Shared { let value: NativeOnly }\n"
    interpolated_reference = 'let text = "value: \\(NativeOnly())"\n'
    platform_source = "import Foundation\nstruct Shared { let text: String; let bytes: Data }\n"

    def test_protocol_actor_enum_and_typealias_are_project_types(self):
        for declaration in (
            "protocol NativeOnly {}", "actor NativeOnly {}",
            "enum NativeOnly {}", "typealias NativeOnly = String",
        ):
            with self.subTest(declaration=declaration):
                self.write(self.origin / "BarnardCore/Only.swift", declaration)
                self.reference(self.missing_reference)
                self.assertEqual(self.check().returncode, 1)


class AndroidMirrorFixtures(MirrorFixtures, unittest.TestCase):
    language = "android"
    suffix = ".kt"
    origin = Path("packages/android/barnard/src/main/kotlin/org/levarac/barnard")
    mirror = Path("packages/dart/barnard/android/src/main/kotlin/org/levarac/barnard")
    source_file = Path("Shared.kt")
    mirror_file = Path("Shared.kt")
    manifest = 'android_mirrored_files=("Shared.kt")\nandroid_react_native_mirrored_files=("ReactOnly.kt")\n'
    shared_source = "package org.levarac.barnard\nclass Shared\n"
    missing_declaration = "package org.levarac.barnard\nclass NativeOnly\n"
    missing_reference = "package org.levarac.barnard\nclass Shared(val value: NativeOnly)\n"
    interpolated_reference = 'val text = "value: ${NativeOnly()}"\n'
    platform_source = "import android.content.Context\nclass Shared(val text: String, val context: Context)\n"

    def setUp(self):
        super().setUp()
        self.write(self.origin / "ReactOnly.kt", "class ReactOnly\n")
        self.write("packages/react-native/barnard/android/src/main/kotlin/org/levarac/barnard/ReactOnly.kt",
                   "class ReactOnly\n")

    def test_interface_object_enum_and_typealias_are_project_types(self):
        for declaration in (
            "interface NativeOnly", "object NativeOnly", "enum class NativeOnly { X }",
            "data class NativeOnly(val x: Int)", "typealias NativeOnly = String",
        ):
            with self.subTest(declaration=declaration):
                self.write(self.origin / "Only.kt", declaration)
                self.reference(self.missing_reference)
                self.assertEqual(self.check().returncode, 1)

    def test_java_project_declaration_is_detected(self):
        self.write("packages/android/barnard/src/main/java/org/levarac/barnard/NativeOnly.java",
                   "package org.levarac.barnard; public class NativeOnly {}")
        self.reference(self.missing_reference)
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("NativeOnly", result.stdout)


if __name__ == "__main__":
    unittest.main()
