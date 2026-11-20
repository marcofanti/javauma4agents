#!/usr/bin/env bash
# Provision Alice's Ed25519 device key for local-key owner authentication.
#
#   certs/owner-ed25519.pem  her private key (mode 600); never leaves her side
#   certs/owner-ed25519.pub  the public half, bind-mounted into uma-as
#
# Idempotent and never rotates: an existing private key is kept, and a missing public
# key is derived from it. Refuses, with a non-zero exit, a directory at either path
# (Docker creates one when Compose bind-mounts a file that does not exist yet, as on a
# Phase A checkout upgraded before this key was provisioned), a public key that does
# not match the private key, and a public key with no private key beside it.
set -euo pipefail

dir="${1:-./certs}"
priv="$dir/owner-ed25519.pem"
pub="$dir/owner-ed25519.pub"

fail() {
	echo "owner-key: $*" >&2
	exit 1
}

for target in "$priv" "$pub"; do
	if [ -e "$target" ] && [ ! -f "$target" ]; then
		fail "$target exists but is not a regular file (Docker creates a directory when a
  bind-mounted file is missing). Keeping every volume, stop the service that mounts it
  (docker compose stop uma-as), remove the empty directory (rmdir '$target'), then
  run make up again. Do not use make down: it deletes the stack's volumes."
	fi
done

mkdir -p "$dir"
tmp="$(mktemp -d "$dir/.owner-key.XXXXXX")"
cleanup() {
	rm -f "$tmp/priv" "$tmp/pub" "$tmp/err"
	rmdir "$tmp"
}
trap cleanup EXIT

derive_public() {
	openssl pkey -in "$priv" -pubout -out "$tmp/pub" 2>"$tmp/err" ||
		fail "could not derive a public key from $priv: $(cat "$tmp/err")"
}

if [ ! -f "$priv" ]; then
	[ ! -e "$pub" ] ||
		fail "$pub exists without $priv. Restore the private key, or move the public
  key aside to make a new pair."
	(umask 077 && openssl genpkey -algorithm ed25519 -out "$tmp/priv" 2>"$tmp/err") ||
		fail "could not generate a key: $(cat "$tmp/err")"
	openssl pkey -in "$tmp/priv" -pubout -out "$tmp/pub" 2>"$tmp/err" ||
		fail "could not derive the public key: $(cat "$tmp/err")"
	chmod 600 "$tmp/priv"
	mv "$tmp/pub" "$pub"
	mv "$tmp/priv" "$priv"
	echo "==> made Alice's device key ($priv, $pub)"
	exit 0
fi

derive_public
if [ ! -f "$pub" ]; then
	mv "$tmp/pub" "$pub"
	echo "==> derived $pub from the existing $priv (not rotated)"
	exit 0
fi

cmp -s "$tmp/pub" "$pub" ||
	fail "$pub does not match $priv. Move one aside; this script does not rotate keys."
echo "==> Alice's device key already exists"
