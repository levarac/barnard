#!/usr/bin/env python3

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_SPEC = importlib.util.spec_from_file_location(
    "b005_generator", ROOT / "scripts/b005-envelope-v2-generator.py"
)
GENERATOR = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = GENERATOR
MODULE_SPEC.loader.exec_module(GENERATOR)


class B005EnvelopeVectorGeneratorTest(unittest.TestCase):
    def test_check_mode_reproduces_committed_vectors(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/b005-envelope-v2-generator.py"), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_signature_mutation_is_rejected(self):
        data = json.loads((ROOT / "scripts/b005-envelope-v2-fixtures.json").read_text())
        envelope = GENERATOR.build_envelope(data, data["v1"])
        mutated = envelope[:-1] + bytes([envelope[-1] ^ 1])
        with self.assertRaises(AssertionError):
            GENERATOR.validate(
                {**data, "event_key_set_digest": "cba59e50c7666ef2468a14f2e53f04decfd078933cd245a9a2d77532eb23b700", "delegate_public_key": data["v2"]["delegate_public_key"]},
                mutated,
                envelope,
            )

    def test_workflow_path_filters_name_only_existing_inputs(self):
        workflow = (ROOT / ".github/workflows/b005-envelope-vectors.yml").read_text()
        for path in (
            "scripts/b005-envelope-v2-generator.py",
            "scripts/b005-envelope-v2-fixtures.json",
            "scripts/tests/test_b005_envelope_v2_generator.py",
            "test-vectors/b005-envelope-v2.txt",
            ".github/workflows/b005-envelope-vectors.yml",
        ):
            self.assertIn(f'"{path}"', workflow)
            self.assertTrue((ROOT / path).exists(), path)


if __name__ == "__main__":
    unittest.main()
