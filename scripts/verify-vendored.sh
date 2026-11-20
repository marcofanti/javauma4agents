#!/usr/bin/env bash
# Verify that every file listed in conformance/upstream/MANIFEST matches its
# pinned upstream git blob hash, and that no unlisted file was added.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
dest="$root/conformance/upstream"
manifest="$dest/MANIFEST"
status=0
expected_paths=$(awk '!/^#/ {sub(/^[^ ]+ /, ""); print}' "$manifest")

while read -r expected file; do
	actual=$(git hash-object "$dest/$file" 2>/dev/null || echo missing)
	if [[ "$actual" != "$expected" ]]; then
		echo "MISMATCH $file: expected $expected, found $actual" >&2
		status=1
	fi
done < <(grep -v '^#' "$manifest")

while IFS= read -r file; do
	if ! grep -Fqx -- "$file" <<<"$expected_paths"; then
		echo "UNLISTED $file: not in MANIFEST; vendored files must come from the pin" >&2
		status=1
	fi
done < <(cd "$dest" && find . -type f -not -path './MANIFEST' -not -path './README.md' \
	-not -path './clients/ts-agent/node_modules/*' -not -path './clients/ts-agent/dist/*' \
	-not -path '*/__pycache__/*' | sed 's|^\./||')

if [[ $status -eq 0 ]]; then
	echo "Vendored tree matches $(grep -c -v '^#' "$manifest") pinned upstream blobs"
fi
exit $status
