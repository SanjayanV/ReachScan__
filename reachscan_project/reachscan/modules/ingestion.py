"""
Module 1: Vulnerability Ingestion Engine
Parses dependency manifests and queries OSV.dev for known CVEs.
"""

import re
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Vulnerability:
    cve_id: str
    package: str
    severity: str
    summary: str
    affected_versions: list[str]
    vulnerable_functions: list[str]
    osv_id: str
    cvss_score: float = 0.0
    cvss_vector: str = ""
    fixed_version: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "cve_id": self.cve_id,
            "package": self.package,
            "severity": self.severity,
            "summary": self.summary,
            "affected_versions": self.affected_versions,
            "vulnerable_functions": self.vulnerable_functions,
            "osv_id": self.osv_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "fixed_version": self.fixed_version,
            "references": self.references,
        }


@dataclass
class Dependency:
    name: str
    version: str
    source_file: str = ""
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


KNOWN_SINK_SIGNATURES: dict[str, list[str]] = {
    "pyyaml":        ["yaml.load", "yaml.unsafe_load", "yaml.full_load"],
    "PyYAML":        ["yaml.load", "yaml.unsafe_load", "yaml.full_load"],
    "pickle":        ["pickle.load", "pickle.loads"],
    "shelve":        ["shelve.open"],
    "jsonpickle":    ["jsonpickle.decode"],
    "jinja2":        ["Template", "Environment", "from_string"],
    "Jinja2":        ["Template", "Environment", "from_string"],
    "mako":          ["Template", "MakoTemplate"],
    "requests":      ["requests.get", "requests.post", "requests.put",
                      "requests.delete", "requests.request", "requests.Session",
                      "requests.head", "requests.patch"],
    "urllib3":       ["urllib3.request", "urllib3.PoolManager"],
    "httpx":         ["httpx.get", "httpx.post", "httpx.Client"],
    "aiohttp":       ["aiohttp.ClientSession"],
    "pillow":        ["Image.open", "Image.fromstring", "Image.frombuffer",
                      "Image.frombytes"],
    "Pillow":        ["Image.open", "Image.fromstring", "Image.frombuffer",
                      "Image.frombytes"],
    "numpy":         ["numpy.load", "np.load", "numpy.fromstring"],
    "pandas":        ["pandas.read_pickle", "pd.read_pickle"],
    "scipy":         ["scipy.io.loadmat"],
    "cryptography":  ["Cipher", "decrypt", "encrypt", "Fernet"],
    "pycrypto":      ["DES.new", "AES.new"],
    "pycryptodome":  ["DES.new", "AES.new"],
    "flask":         ["Flask", "render_template_string", "make_response"],
    "django":        ["mark_safe", "RawSQL"],
    "subprocess":    ["subprocess.call", "subprocess.Popen", "subprocess.run"],
    "paramiko":      ["SSHClient", "Transport"],
}

OSV_API_URL = "https://api.osv.dev/v1/query"
MAX_RETRIES = 3
RETRY_BACKOFF = 1.5


def parse_requirements(req_file: str) -> list[Dependency]:
    deps = []
    path = Path(req_file)

    if not path.exists():
        raise FileNotFoundError(f"Requirements file not found: {req_file}")

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([=<>!~]+)\s*([\d\.]+)", line)
            if match:
                name = match.group(1)
                version = match.group(3)
                deps.append(Dependency(name=name, version=version, source_file=str(path)))
            else:
                name_match = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
                if name_match:
                    deps.append(Dependency(name=name_match.group(1), version="*",
                                           source_file=str(path)))

    return deps


def parse_pipfile(pipfile_path: str) -> list[Dependency]:
    deps = []
    path = Path(pipfile_path)
    if not path.exists():
        return deps

    in_packages = False
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line == "[packages]":
                in_packages = True
                continue
            elif line.startswith("["):
                in_packages = False
                continue

            if in_packages and "=" in line:
                parts = line.split("=", 1)
                name = parts[0].strip().strip('"')
                version = parts[1].strip().strip('"').lstrip("=~><!")
                if version == "*":
                    version = "*"
                deps.append(Dependency(name=name, version=version,
                                       source_file=str(path)))

    return deps


def parse_pyproject_toml(toml_path: str) -> list[Dependency]:
    deps = []
    path = Path(toml_path)
    if not path.exists():
        return deps

    in_deps = False
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line == "dependencies = [":
                in_deps = True
                continue
            elif in_deps and line == "]":
                in_deps = False
                continue

            if in_deps:
                dep_str = line.strip(",").strip().strip('"').strip("'")
                match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([=<>!~]+)\s*([\d\.]+)", dep_str)
                if match:
                    deps.append(Dependency(name=match.group(1), version=match.group(3),
                                           source_file=str(path)))
                else:
                    name_match = re.match(r"^([A-Za-z0-9_\-\.]+)", dep_str)
                    if name_match and name_match.group(1):
                        deps.append(Dependency(name=name_match.group(1), version="*",
                                               source_file=str(path)))

    return deps


def find_and_parse_manifests(directory: str, req_file: str = None) -> list[Dependency]:
    deps = []

    if req_file:
        deps.extend(parse_requirements(req_file))
    else:
        req_path = Path(directory) / "requirements.txt"
        if req_path.exists():
            deps.extend(parse_requirements(str(req_path)))

    pipfile_path = Path(directory) / "Pipfile"
    if pipfile_path.exists():
        deps.extend(parse_pipfile(str(pipfile_path)))

    pyproject_path = Path(directory) / "pyproject.toml"
    if pyproject_path.exists():
        deps.extend(parse_pyproject_toml(str(pyproject_path)))

    seen = {}
    unique = []
    for d in deps:
        key = d.name.lower()
        if key not in seen or (seen[key].version == "*" and d.version != "*"):
            seen[key] = d
            unique.append(d)
        elif key in seen and seen[key] is not unique[-1] if unique else True:
            pass

    return list(seen.values())


def query_osv(package_name: str, version: str) -> list[dict]:
    payload = json.dumps({
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": version if version != "*" else None
    }).encode("utf-8")

    req = urllib.request.Request(
        OSV_API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    for attempt in range(MAX_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("vulns", [])
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503) and attempt < MAX_RETRIES - 1:
                wait = RETRY_BACKOFF * (2 ** attempt)
                time.sleep(wait)
                continue
            return []
        except urllib.error.URLError:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_BACKOFF)
                continue
            return []
        except Exception:
            return []

    return []


def parse_cvss_score(cvss_vector: str) -> float:
    if not cvss_vector:
        return 0.0

    try:
        return float(cvss_vector)
    except ValueError:
        pass

    parts = cvss_vector.split("/")
    for part in reversed(parts):
        try:
            score = float(part)
            if 0.0 <= score <= 10.0:
                return score
        except ValueError:
            continue

    return 0.0


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "UNKNOWN"


def extract_severity(osv_entry: dict) -> tuple[str, float, str]:
    best_score = 0.0
    best_vector = ""

    for sev in osv_entry.get("severity", []):
        score_str = sev.get("score", "")
        score = parse_cvss_score(score_str)
        if score > best_score:
            best_score = score
            best_vector = score_str

    db_specific = osv_entry.get("database_specific", {})
    if "severity" in db_specific:
        sev_str = db_specific["severity"].upper()
        if sev_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if best_score == 0.0:
                approx = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 2.5}
                best_score = approx.get(sev_str, 0.0)
                return sev_str, best_score, best_vector

    if best_score > 0.0:
        return score_to_severity(best_score), best_score, best_vector

    for alias in osv_entry.get("aliases", []):
        if alias.startswith("CVE"):
            return "HIGH", 7.0, ""

    return "UNKNOWN", 0.0, ""


def extract_cve_id(osv_entry: dict) -> str:
    for alias in osv_entry.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return osv_entry.get("id", "UNKNOWN")


def extract_fixed_version(osv_entry: dict) -> str:
    for affected in osv_entry.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return ""


def extract_references(osv_entry: dict) -> list[str]:
    refs = []
    for ref in osv_entry.get("references", []):
        url = ref.get("url", "")
        if url:
            refs.append(url)
    return refs[:5]


def get_vulnerable_functions(package_name: str, osv_entry: dict) -> list[str]:
    funcs = []

    for key in [package_name, package_name.lower(), package_name.replace("-", "_")]:
        if key in KNOWN_SINK_SIGNATURES:
            funcs.extend(KNOWN_SINK_SIGNATURES[key])
            break

    details = osv_entry.get("details", "") + " " + osv_entry.get("summary", "")
    func_hints = re.findall(r"`([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*)\(\)`", details, re.IGNORECASE)
    for hint in func_hints:
        if hint not in funcs:
            funcs.append(hint)

    return list(set(funcs)) if funcs else [f"{package_name.lower()}.*"]


def run_ingestion(req_file: str, verbose: bool = True) -> tuple[list[Dependency], list[Vulnerability]]:
    if verbose:
        print("\n╔══════════════════════════════════════════════╗")
        print("║   MODULE 1: Vulnerability Ingestion Engine   ║")
        print("╚══════════════════════════════════════════════╝")

    deps = parse_requirements(req_file)
    all_vulns = []

    if verbose:
        print(f"\n  [*] Found {len(deps)} dependencies in {req_file}")
        print("  [*] Querying OSV.dev API...\n")

    for dep in deps:
        if verbose:
            print(f"  → Scanning {dep.name}=={dep.version}...", end=" ", flush=True)

        osv_results = query_osv(dep.name, dep.version)

        if osv_results:
            if verbose:
                print(f"⚠  {len(osv_results)} vulnerability(ies) found")
            for entry in osv_results:
                severity, cvss_score, cvss_vector = extract_severity(entry)
                vuln = Vulnerability(
                    cve_id=extract_cve_id(entry),
                    package=dep.name,
                    severity=severity,
                    summary=entry.get("summary", "No summary available")[:250],
                    affected_versions=[dep.version],
                    vulnerable_functions=get_vulnerable_functions(dep.name, entry),
                    osv_id=entry.get("id", ""),
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    fixed_version=extract_fixed_version(entry),
                    references=extract_references(entry),
                )
                dep.vulnerabilities.append(vuln)
                all_vulns.append(vuln)
        else:
            if verbose:
                print("✓ No known vulnerabilities")

    if verbose:
        print(f"\n  [✓] Ingestion complete. Total CVEs found: {len(all_vulns)}")

    return deps, all_vulns
