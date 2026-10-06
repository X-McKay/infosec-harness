#!/usr/bin/env bash
# Build the patched gateway through the qualified build-egress builder. Requires the private
# build context under .harness/openshell/gateway-build/: src/ (upstream clone at the pinned
# commit) and vendor/ (cargo vendor --locked of that clone). Patches come from this directory.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT"
# A worktree may build against the main checkout's managed state: HARNESS_DIR=/path/.harness
HARNESS_DIR="${HARNESS_DIR:-$ROOT/.harness}"
BUILD="$HARNESS_DIR/openshell/gateway-build"
PINNED="$(python3 -c 'import json;print(json.load(open(".dev-tools/openshell.json"))["commit"])')"
ACTUAL="$(git -C "$BUILD/src" rev-parse HEAD)"
[[ "$ACTUAL" == "$PINNED" ]] || { echo "gateway-build/src is at $ACTUAL, expected pinned $PINNED" >&2; exit 2; }
[[ -z "$(git -C "$BUILD/src" status --porcelain)" ]] || { echo "gateway-build/src must be a clean checkout" >&2; exit 2; }
[[ -d "$BUILD/vendor" ]] || { echo "run: (cd $BUILD/src && cargo vendor --locked ../vendor)" >&2; exit 2; }
command rm -rf "$BUILD/patches" "$BUILD/out"
mkdir -p "$BUILD/patches"
command cp deploy/openshell/patches/*.patch "$BUILD/patches/"
printf 'src/.git\nsrc/target\nprobe\nout\n' > "$BUILD/.dockerignore"
set -a; source "$HARNESS_DIR/dev.env"; set +a
"$HARNESS_DIR/bin/docker" buildx build --builder "$HARNESS_BUILDX_BUILDER" \
  --build-arg HTTP_PROXY="$HARNESS_BUILD_EGRESS_PROXY" --build-arg HTTPS_PROXY="$HARNESS_BUILD_EGRESS_PROXY" \
  --build-arg CARGO_JOBS="${CARGO_JOBS:-4}" --progress plain \
  -f deploy/openshell/Dockerfile.gateway --output "type=local,dest=$BUILD/out" "$BUILD"
python3 - "$BUILD" "$PINNED" <<'PY'
import hashlib, json, re, sys, time
from pathlib import Path
build, commit = Path(sys.argv[1]), sys.argv[2]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
image = re.search(r"RUST_IMAGE=(\S+)", Path("deploy/openshell/Dockerfile.gateway").read_text()).group(1)
record = {"upstream_commit": commit, "rust_image": image, "features": ["default", "bundled-z3"],
          "patches": {p.name: sha(p) for p in sorted(build.glob("patches/*.patch"))},
          "binary_sha256": sha(build / "out/openshell-gateway"),
          "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
(build / "out/gateway-build.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record, indent=2))
PY
