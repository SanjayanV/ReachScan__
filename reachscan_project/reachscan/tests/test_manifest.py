"""Tests for dependency-manifest parsing."""

import unittest

from providers.manifest import (
    discover_manifests,
    parse_pipfile,
    parse_pyproject_toml,
    parse_requirements,
)
from utils.exceptions import ManifestNotFoundError
from tests.helpers import TempProject


class RequirementsTest(unittest.TestCase):
    def test_parse_pinned_versions(self):
        with TempProject() as p:
            p.write("requirements.txt",
                    "PyYAML==5.3.1\nnumpy>=1.21\nrequests\n# comment\n\n")
            deps = parse_requirements(str(p.root / "requirements.txt"))
            by_name = {d.name: d for d in deps}
            self.assertEqual(by_name["PyYAML"].version, "5.3.1")
            self.assertEqual(by_name["numpy"].version, "1.21")
            self.assertEqual(by_name["requests"].version, "*")

    def test_missing_file_raises(self):
        with TempProject() as p:
            with self.assertRaises(ManifestNotFoundError):
                parse_requirements(str(p.root / "nope.txt"))

    def test_ignores_comments_and_flags(self):
        with TempProject() as p:
            p.write("requirements.txt",
                    "# comment\n-r other.txt\n--index-url https://x\nfoo==1.0\n")
            deps = parse_requirements(str(p.root / "requirements.txt"))
            self.assertEqual([d.name for d in deps], ["foo"])


class PipfileTest(unittest.TestCase):
    def test_parses_packages(self):
        with TempProject() as p:
            p.write("Pipfile",
                    "[packages]\nrequests = \"==2.28.0\"\nflask = \"==2.0.0\"\n\n[dev-packages]\npytest = \"*\"\n")
            deps = parse_pipfile(str(p.root / "Pipfile"))
            self.assertEqual({d.name: d.version for d in deps},
                             {"requests": "2.28.0", "flask": "2.0.0"})


class PyprojectTest(unittest.TestCase):
    def test_parses_without_tomllib(self):
        with TempProject() as p:
            p.write("pyproject.toml",
                    '[project]\ndependencies = [\n    "httpx==0.24.0",\n]\n')
            deps = parse_pyproject_toml(str(p.root / "pyproject.toml"))
            self.assertEqual(deps[0].name, "httpx")
            self.assertEqual(deps[0].version, "0.24.0")


class DiscoverTest(unittest.TestCase):
    def test_dedupes_preferring_pinned(self):
        with TempProject() as p:
            p.write("requirements.txt", "foo==1.2.3\nfoo:\n")
            deps = discover_manifests(str(p.root))
            foos = [d for d in deps if d.name.lower() == "foo"]
            self.assertEqual(len(foos), 1)
            self.assertEqual(foos[0].version, "1.2.3")


if __name__ == "__main__":
    import unittest
    unittest.main()