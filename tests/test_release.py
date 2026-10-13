"""Release-conformance tests (Linie 0.11.x): docs + packaging gates."""
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as handle:
        return handle.read()


class LicenseBriefTest(unittest.TestCase):
    CANDIDATES = ("MIT", "Apache-2.0", "EUPL-1.2", "GPLv3")

    def test_brief_exists_and_names_candidates(self):
        brief = _read(os.path.join("docs", "LIZENZ-ENTSCHEIDUNG.md"))
        for candidate in self.CANDIDATES:
            with self.subTest(candidate=candidate):
                self.assertIn(candidate, brief)

    def test_brief_has_decision_checkbox(self):
        brief = _read(os.path.join("docs", "LIZENZ-ENTSCHEIDUNG.md"))
        self.assertIn("- [x] Gewählte Lizenz: EUPL-1.2", brief)
        self.assertIn("PascalIO", brief)
        self.assertIn("0.11.1", brief)

    def test_changelog_covers_release_line(self):
        changelog = _read("CHANGELOG.md")
        self.assertIn("## 0.11.0", changelog)
        self.assertIn("## 0.11.1", changelog)


class LicenseAppliedTest(unittest.TestCase):
    def test_license_full_text_present(self):
        text = _read("LICENSE")
        self.assertIn("EUROPEAN UNION PUBLIC LICENCE v. 1.2", text)
        self.assertIn("Copyright (c) 2026 PascalIO", text)
        self.assertIn("Licensed under the EUPL-1.2", text)
        for article in range(1, 16):
            with self.subTest(article=article):
                self.assertIn(f"\n{article}. ", text)
        self.assertIn("\nAppendix\n", text)
        self.assertIn("Compatible Licences", text)

    def test_pyproject_declares_eupl(self):
        pyproject = _read("pyproject.toml")
        self.assertIn('license = { text = "EUPL-1.2" }', pyproject)
        self.assertIn(
            "European Union Public Licence 1.2 (EUPL 1.2)", pyproject
        )

    def test_readme_has_license_chapter(self):
        readme = _read("README.md")
        self.assertIn("## Lizenz", readme)
        self.assertIn("EUPL-1.2", readme)
        self.assertIn("PascalIO", readme)
        self.assertIn("LICENSE", readme)


class VersionConsistencyTest(unittest.TestCase):
    def test_version_is_xyz(self):
        import re

        from ptt import __version__

        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")

    def test_pyproject_takes_version_from_package(self):
        pyproject = _read("pyproject.toml")
        self.assertIn('dynamic = ["version"]', pyproject)
        self.assertIn('[tool.setuptools.dynamic]', pyproject)
        self.assertIn('version = { attr = "ptt.__version__" }', pyproject)

    def test_pyproject_has_no_static_version(self):
        in_project = False
        for line in _read("pyproject.toml").splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                in_project = stripped == "[project]"
            elif in_project and stripped.startswith("version"):
                self.fail(f"statische Version in [project]: {line!r}")


class PackagingTest(unittest.TestCase):
    def test_build_floor_supports_license_files(self):
        pyproject = _read("pyproject.toml")
        self.assertIn('"setuptools>=77"', pyproject)
        self.assertIn('license-files = ["LICENSE*"]', pyproject)


class CiWorkflowTest(unittest.TestCase):
    def test_ci_checks_metadata(self):
        ci = _read(os.path.join(".github", "workflows", "ci.yml"))
        self.assertIn("prepare_metadata_for_build_wheel", ci)
        self.assertIn("__version__", ci)

    def test_ci_runs_doctor_self_test(self):
        ci = _read(os.path.join(".github", "workflows", "ci.yml"))
        self.assertIn("python -m ptt doctor --self-test", ci)

    def test_release_gates_tag_vs_version(self):
        release = _read(
            os.path.join(".github", "workflows", "release.yml")
        )
        self.assertIn("GITHUB_REF_NAME", release)
        self.assertIn("__version__", release)


class CompatMatrixTest(unittest.TestCase):
    def _matrix(self):
        return _read(
            os.path.join("docs", "KOMPATIBILITAET.md")
        )

    def test_names_tested_platforms(self):
        matrix = self._matrix()
        for token in ("Linux", "Windows", "3.9", "3.13", "macOS"):
            with self.subTest(token=token):
                self.assertIn(token, matrix)

    def test_names_protocol_and_legacy(self):
        matrix = self._matrix()
        for token in ("ptt1-shell", "ptt1-transfer", "legacy"):
            with self.subTest(token=token):
                self.assertIn(token, matrix)

    def test_names_feature_gates(self):
        matrix = self._matrix()
        for token in ("0.8", "0.9.2"):
            with self.subTest(token=token):
                self.assertIn(token, matrix)


class MessageConsistencyTest(unittest.TestCase):
    def _sources(self):
        import glob

        texts = {}
        for path in glob.glob(
            os.path.join(ROOT, "ptt", "*.py")
        ):
            with open(path, encoding="utf-8") as handle:
                texts[path] = handle.read()
        self.assertTrue(texts)
        return texts

    def test_next_step_spelling_singular(self):
        found = 0
        for path, text in self._sources().items():
            with self.subTest(path=os.path.basename(path)):
                self.assertNotIn("Nächste Schritte", text)
                self.assertNotIn("Naechster Schritt", text)
                found += text.count("Nächster Schritt:")
        self.assertGreater(found, 0)

    def test_single_line_cli_errors_without_period(self):
        import re

        literal = re.compile(r"""parser\.error\(["']([^"']+)["']\)""")
        with open(
            os.path.join(ROOT, "ptt", "cli.py"), encoding="utf-8"
        ) as handle:
            cli = handle.read()
        errors = literal.findall(cli)
        self.assertGreater(len(errors), 5)
        for message in errors:
            with self.subTest(message=message):
                self.assertFalse(
                    message.endswith("."),
                    f"parser.error mit Punkt: {message!r}",
                )


class TimeoutReviewTest(unittest.TestCase):
    def test_self_test_budget_holds(self):
        from ptt.doctor import SELF_TEST_STEP_TIMEOUT, SELF_TEST_TIMEOUT

        self.assertGreater(
            SELF_TEST_TIMEOUT, 3 * SELF_TEST_STEP_TIMEOUT
        )

    def test_timeout_constants_positive(self):
        from ptt.client import RETRY_BACKOFF_CAP
        from ptt.discover import DISCOVER_TIMEOUT
        from ptt.doctor import SELF_TEST_STEP_TIMEOUT, SELF_TEST_TIMEOUT
        from ptt.host import (
            AUTH_TIMEOUT,
            READER_JOIN_TIMEOUT,
            SHUTDOWN_JOIN_TIMEOUT,
        )
        from ptt.protocol import KEEPALIVE_AFTER, KEEPALIVE_INTERVAL
        from ptt.transfer import TRANSFER_ACK_TIMEOUT
        from ptt.update import UPDATE_TIMEOUT

        for name, value in (
            ("RETRY_BACKOFF_CAP", RETRY_BACKOFF_CAP),
            ("DISCOVER_TIMEOUT", DISCOVER_TIMEOUT),
            ("SELF_TEST_TIMEOUT", SELF_TEST_TIMEOUT),
            ("SELF_TEST_STEP_TIMEOUT", SELF_TEST_STEP_TIMEOUT),
            ("AUTH_TIMEOUT", AUTH_TIMEOUT),
            ("READER_JOIN_TIMEOUT", READER_JOIN_TIMEOUT),
            ("SHUTDOWN_JOIN_TIMEOUT", SHUTDOWN_JOIN_TIMEOUT),
            ("KEEPALIVE_AFTER", KEEPALIVE_AFTER),
            ("KEEPALIVE_INTERVAL", KEEPALIVE_INTERVAL),
            ("TRANSFER_ACK_TIMEOUT", TRANSFER_ACK_TIMEOUT),
            ("UPDATE_TIMEOUT", UPDATE_TIMEOUT),
        ):
            with self.subTest(name=name):
                self.assertGreater(value, 0)

    def test_timeouts_doc_names_constants(self):
        doc = _read(os.path.join("docs", "TIMEOUTS.md"))
        for token in (
            "SELF_TEST_TIMEOUT",
            "RETRY_BACKOFF_CAP",
            "AUTH_TIMEOUT",
            "TRANSFER_ACK_TIMEOUT",
            "--timeout",
            "124",
        ):
            with self.subTest(token=token):
                self.assertIn(token, doc)


class SecurityReviewTest(unittest.TestCase):
    def test_rate_limit_numbers_match_docs(self):
        from ptt.host import (
            BACKOFF_MAX_SECONDS,
            PIN_MAX_FAILURES,
            PIN_WINDOW_SECONDS,
        )

        self.assertEqual(PIN_MAX_FAILURES, 5)
        self.assertEqual(PIN_WINDOW_SECONDS, 300)
        self.assertEqual(BACKOFF_MAX_SECONDS, 30.0)

    def test_pin_is_six_digits(self):
        import re

        from ptt.auth import generate_pin

        for _ in range(25):
            self.assertRegex(generate_pin(), r"^\d{6}$")

    def test_security_doc_reset_shipped(self):
        from ptt.cli import build_parser

        doc = _read("SECURITY.md")
        self.assertIn("(ab 0.11.8)", doc)
        args = build_parser().parse_args(["reset", "--dry-run"])
        self.assertTrue(args.dry_run)


class UpgradePathTest(unittest.TestCase):
    def test_finale_changelog_covers_release_line(self):
        changelog = _read("CHANGELOG.md")
        for minor in range(11):
            version = f"0.11.{minor}"
            with self.subTest(version=version):
                self.assertIn(f"## {version}", changelog)

    def test_finale_readme_documents_reset(self):
        readme = _read("README.md")
        self.assertIn("ptt reset", readme)

    def test_upgrade_doc_covers_changes(self):
        doc = _read(os.path.join("docs", "UPGRADE.md"))
        for token in (
            "0.5.3",
            "0.5.6",
            "0.6.4",
            "0.7.5",
            "0.8.7",
            "0.8.9",
            "0.9.5",
            "0.9.6",
            "0.11.1",
            "124",
            "128+N",
            ".ptt-part",
            "PTT_HOST",
            "EUPL",
            "ptt update",
            "ptt reset",
            "ptt doctor",
        ):
            with self.subTest(token=token):
                self.assertIn(token, doc)


if __name__ == "__main__":
    unittest.main()
