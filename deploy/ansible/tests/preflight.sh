#!/usr/bin/env bash
# Checks the role's preflight assert without Docker or a target host.
# Needs ansible-core only. Run from anywhere.
set -u
cd "$(dirname "$0")"
# The role directory must be named psina for include_role.
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
ln -s "$(cd .. && pwd)" "$tmp/psina"
export ANSIBLE_ROLES_PATH="$tmp"

run() { ansible-playbook -i localhost, preflight.yml "$@" 2>&1; }
fail=0

out=$(run); rc=$?
if [ $rc -eq 0 ] || ! grep -q psina_jwt_private_key <<<"$out"; then
  echo "FAIL: empty key must fail naming psina_jwt_private_key (rc=$rc)"; fail=1
fi

out=$(run -e 'psina_jwt_private_key=" "'); rc=$?
if [ $rc -eq 0 ]; then echo "FAIL: blank key must fail"; fail=1; fi

out=$(run -e psina_jwt_private_key=pem); rc=$?
if [ $rc -ne 0 ]; then echo "FAIL: set key must pass"; echo "$out"; fail=1; fi

out=$(run -e psina_dev=true); rc=$?
if [ $rc -ne 0 ]; then echo "FAIL: dev mode must pass without a key"; echo "$out"; fail=1; fi

[ $fail -eq 0 ] && echo "preflight: ok"
exit $fail
