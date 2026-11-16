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
# Passed to every case that is meant to pass or to fail for the key alone.
pw='psina_db_password=not-the-default'

out=$(run -e "$pw"); rc=$?
if [ $rc -eq 0 ] || ! grep -q psina_jwt_private_key <<<"$out"; then
  echo "FAIL: empty key must fail naming psina_jwt_private_key (rc=$rc)"; fail=1
fi

out=$(run -e "$pw" -e 'psina_jwt_private_key=" "'); rc=$?
if [ $rc -eq 0 ]; then echo "FAIL: blank key must fail"; fail=1; fi

out=$(run -e "$pw" -e '{"psina_jwt_private_key": null}'); rc=$?
if [ $rc -eq 0 ]; then echo "FAIL: null key must fail"; fail=1; fi

out=$(run -e "$pw" -e psina_jwt_private_key=pem); rc=$?
if [ $rc -ne 0 ]; then echo "FAIL: set key must pass"; echo "$out"; fail=1; fi

out=$(run -e "$pw" -e psina_dev=true); rc=$?
if [ $rc -ne 0 ]; then echo "FAIL: dev mode must pass without a key"; echo "$out"; fail=1; fi

# The shipped default password is public: only a dev stand may keep it.
out=$(run -e psina_jwt_private_key=pem); rc=$?
if [ $rc -eq 0 ] || ! grep -q psina_db_password <<<"$out"; then
  echo "FAIL: default password must fail naming psina_db_password (rc=$rc)"; fail=1
fi

out=$(run -e psina_jwt_private_key=pem -e psina_dev=true); rc=$?
if [ $rc -ne 0 ]; then echo "FAIL: dev mode must keep the default password"; echo "$out"; fail=1; fi

out=$(run -e psina_jwt_private_key=pem -e psina_dev=false); rc=$?
if [ $rc -eq 0 ]; then echo "FAIL: explicit psina_dev=false must reject the default password"; fail=1; fi

[ $fail -eq 0 ] && echo "preflight: ok"
exit $fail
