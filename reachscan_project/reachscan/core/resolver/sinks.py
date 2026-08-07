"""Known sink signatures used to enrich a vulnerability with function names."""

from __future__ import annotations

import re

# Mapping of distribution name -> function signatures that are historically
# vulnerable. Used to derive ``vulnerable_functions`` when an advisory does
# not name functions explicitly.
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

_FUNCTION_HINT_RE = re.compile(
    r"`([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*)\(\)`", re.IGNORECASE
)


def get_vulnerable_functions(package_name: str, detail_text: str = "") -> list[str]:
    """Return the function signatures associated with a package.

    Known signatures are combined with back-ticked ``func()`` names found in
    the advisory text. Returns ``[<package>.*]`` as a fallback so reachability
    analysis can still look for the package root.
    """
    funcs: list[str] = []

    for key in [package_name, package_name.lower(), package_name.replace("-", "_")]:
        if key in KNOWN_SINK_SIGNATURES:
            funcs.extend(KNOWN_SINK_SIGNATURES[key])
            break

    for hint in _FUNCTION_HINT_RE.findall(detail_text):
        if hint not in funcs:
            funcs.append(hint)

    return list(set(funcs)) if funcs else [f"{package_name.lower()}.*"]