"""Bounded GET-only readiness check; never claims a worker or model was qualified."""

import argparse
import time

import httpx


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--web-url", required=True)
    args = parser.parse_args()
    deadline = time.monotonic() + 120
    with httpx.Client(timeout=5, trust_env=False) as client:
        while True:
            try:
                health = client.get(args.api_url + "/api/health")
                health.raise_for_status()
                if health.json().get("status") != "control_plane_ready":
                    raise ValueError("Temporal is not ready")
                ui = client.get(args.web_url)
                ui.raise_for_status()
                if '<div id="root"></div>' not in ui.text:
                    raise ValueError("UI document missing")
                print("API, Temporal connectivity and UI document: passed")
                print("Worker execution, OpenShell and live inference: not_checked")
                return
            except (httpx.HTTPError, ValueError):
                if time.monotonic() >= deadline:
                    raise SystemExit("Control-plane readiness failed within 120 seconds") from None
                time.sleep(2)


if __name__ == "__main__":
    main()
