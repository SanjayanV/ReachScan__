"""
data_processor.py — Batch data processing utilities.

VULNERABILITY: Uses numpy.load() with allow_pickle=True.
CVE-2021-41496 (NumPy): Arbitrary code execution via crafted .npy file.

⚠️  INTENTIONAL DESIGN FOR REACHSCAN DEMO:
     batch_process() and load_model_weights() are defined here but are
     NEVER called from app.main() or any other entry point.
     ReachScan should classify this CVE as UNREACHABLE (false positive
     in traditional SCA tools), demonstrating the alert-reduction value.

Call chain: ❌ No path from main() to numpy.load exists.
"""

import numpy as np


def load_model_weights(weights_path: str) -> np.ndarray:
    """
    Load pre-trained model weights from a .npy file.

    ⚠️  VULNERABLE: allow_pickle=True enables deserialization of arbitrary
    Python objects embedded in the .npy file. An attacker who controls
    the weights file can achieve arbitrary code execution.
    CVE-2021-41496.

    Fix: Set allow_pickle=False (default in NumPy >= 1.16.3).
    This function is NEVER called from main(), so despite the CVE,
    ReachScan should mark it UNREACHABLE.
    """
    # SINK: numpy.load with allow_pickle — CVE-2021-41496
    weights = np.load(weights_path, allow_pickle=True)  # noqa
    return weights


def batch_process(data_dir: str) -> list:
    """
    Process a directory of .npy data files.

    Also calls numpy.load internally — same vulnerability.
    This function is also UNREACHABLE from any entry point.
    """
    results = []
    import os
    for fname in os.listdir(data_dir):
        if fname.endswith(".npy"):
            fpath = os.path.join(data_dir, fname)
            # SINK: numpy.load — CVE-2021-41496
            arr = np.load(fpath, allow_pickle=True)  # noqa
            results.append(arr)
    return results


def _internal_helper(arr: np.ndarray) -> float:
    """Internal helper — also unreachable from entry points."""
    return float(np.mean(arr))
