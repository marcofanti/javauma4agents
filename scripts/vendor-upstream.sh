#!/usr/bin/env bash
# Export the pinned upstream check scripts, Python client library,
# TypeScript client, the authorization server's Postgres DDL and pure policy modules
# (vector generation only), and the portal SPA into
# conformance/upstream/, and record each file's
# upstream path and git blob hash in conformance/upstream/MANIFEST.
#
# Usage: scripts/vendor-upstream.sh <upstream-repo> <pin>
set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 <upstream-repo> <pin>" >&2
	exit 2
fi

upstream_repo=$1
pin=$2
root=$(cd "$(dirname "$0")/.." && pwd)
dest="$root/conformance/upstream"

vendored_paths() {
	git -C "$upstream_repo" ls-tree -r --name-only "$pin" -- \
		clients/demo-driver clients/agent-shim/test_shim.py clients/ts-agent lib \
		services/uma-as/schema.sql services/uma-as/policy.py services/uma-as/assurance.py \
		services/uma-as/introduction.py services/alice-portal/static \
		services/org-console/static services/org-authority/org.rego kwaai \
		clients/owner-cli/owner.py integrations/conformance.py \
		integrations/n8n/workflow-template.json integrations/n8n/lab/e2e-workflow.json \
		integrations/n8n/lab/e2e-credentials.json |
		grep -v -E '^lib/test_' |
		grep -v -E '/node_modules/'
}

full_pin=$(git -C "$upstream_repo" rev-parse --verify "$pin^{commit}")
mkdir -p "$dest"
find "$dest" -mindepth 1 -not -path "$dest/README.md" -delete

manifest="$dest/MANIFEST"
printf '# upstream nickgamb/uma4agents %s\n# <git blob sha1> <path>\n' "$full_pin" >"$manifest"
while IFS= read -r file; do
	mkdir -p "$dest/$(dirname "$file")"
	git -C "$upstream_repo" show "$full_pin:$file" >"$dest/$file"
	blob=$(git -C "$upstream_repo" rev-parse "$full_pin:$file")
	printf '%s %s\n' "$blob" "$file" >>"$manifest"
done < <(vendored_paths)

echo "Vendored $(grep -c -v '^#' "$manifest") files from $full_pin into $dest"
