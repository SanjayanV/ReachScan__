
import os
import sys
import argparse

from config import load_config, validate_config
from image_handler import process_image, generate_thumbnail
from web_utils import fetch_data, post_report, render_dashboard

# NOTE: data_processor is imported but its functions are never called from main().
# This tests that ReachScan correctly marks numpy.load as UNREACHABLE even though
# the module is imported at the top level.
import data_processor  # noqa: F401  (imported, not called)


# ─── Application constants ────────────────────────────────────────────────────

CONFIG_FILE   = "config.yaml"
SAMPLE_IMAGE  = "sample.jpg"
API_ENDPOINT  = "https://api.example.com/data"
REPORT_URL    = "https://internal.corp/reports"

DASHBOARD_TEMPLATE = """
<div class="user-panel" {{ user | xmlattr }}>
  <h2>Welcome, {{ user.name }}</h2>
  <p>Role: {{ user.role }}</p>
</div>
"""


# ─── Application logic ────────────────────────────────────────────────────────

def startup_check() -> bool:
    """Verify required files exist before running."""
    checks = [CONFIG_FILE]
    for path in checks:
        if not os.path.exists(path):
            print(f"[!] Missing required file: {path}")
            return False
    return True


def run_pipeline(args) -> dict:
    """
    Main application pipeline. Orchestrates all modules.

    This is the primary entry point — ReachScan should trace
    all vulnerability-relevant call chains from here.
    """
    results = {}

    # ── Step 1: Load config ─────────────────────────────────────────────────
    # CALL CHAIN → load_config() → yaml.load()   [CVE-2020-14343 REACHABLE]
    print("[1/5] Loading configuration...")
    try:
        config = load_config(CONFIG_FILE)
        validate_config(config)
        results["config"] = "ok"
    except FileNotFoundError:
        # Config file missing is expected in demo mode
        config = {"db_host": "localhost", "db_port": 5432, "secret_key": "demo"}
        results["config"] = "demo-defaults"

    # ── Step 2: Process user image ──────────────────────────────────────────
    # CALL CHAIN → process_image() → Image.open()      [CVE-2022-22817 REACHABLE]
    # CALL CHAIN → generate_thumbnail() → Image.open() [CVE-2022-22817 REACHABLE]
    print("[2/5] Processing image...")
    if os.path.exists(SAMPLE_IMAGE):
        meta = process_image(SAMPLE_IMAGE)
        thumb = generate_thumbnail(SAMPLE_IMAGE)
        results["image"] = meta
    else:
        results["image"] = "skipped (no sample.jpg)"

    # ── Step 3: Fetch external data ─────────────────────────────────────────
    # CALL CHAIN → fetch_data() → requests.get()  [CVE-2023-32681 REACHABLE]
    print("[3/5] Fetching external data...")
    proxy = os.environ.get("HTTP_PROXY")
    try:
        data = fetch_data(API_ENDPOINT, proxy=proxy)
        results["api_data"] = data
    except Exception as e:
        results["api_data"] = f"skipped ({e})"

    # ── Step 4: Render dashboard ────────────────────────────────────────────
    # CALL CHAIN → render_dashboard() → Environment() [CVE-2024-34064 REACHABLE]
    print("[4/5] Rendering dashboard...")
    user_attrs = {
        "name": args.username if hasattr(args, "username") else "demo_user",
        "role": "admin",
        "data-user-id": "42",
    }
    html_fragment = render_dashboard(user_attrs, DASHBOARD_TEMPLATE)
    results["dashboard_html"] = html_fragment[:80] + "..."

    # ── Step 5: Post report ─────────────────────────────────────────────────
    # CALL CHAIN → post_report() → requests.post() [CVE-2023-32681 REACHABLE]
    print("[5/5] Posting report...")
    try:
        ok = post_report(REPORT_URL, results)
        results["report_posted"] = ok
    except Exception as e:
        results["report_posted"] = f"skipped ({e})"

    # ── NOT CALLED: data_processor.batch_process() / load_model_weights() ──
    # numpy.load() exists in data_processor.py but is never called from here.
    # CVE-2021-41496 should be marked UNREACHABLE by ReachScan.

    return results


def main():
    parser = argparse.ArgumentParser(description="ReachScan Demo App")
    parser.add_argument("--username", default="demo_user")
    parser.add_argument("--config",   default=CONFIG_FILE)
    args = parser.parse_args()

    print("=" * 60)
    print("  ReachScan Demo Application")
    print("  ⚠️  FOR SECURITY TESTING PURPOSES ONLY")
    print("=" * 60)

    results = run_pipeline(args)

    print("\n[✓] Pipeline complete.")
    for k, v in results.items():
        print(f"    {k}: {v}")


if __name__ == "__main__":
    main()
