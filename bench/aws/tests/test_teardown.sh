#!/usr/bin/env bash
# Checks that s3-ena-probe.sh deletes every AWS resource it created, both when it succeeds and
# when a step fails midway. aws, ssh, scp and curl are shims that log their arguments to $CALLS.
set -euo pipefail
cd "$(dirname "$0")"

SHIMS=$(mktemp -d)
RESULTS_DIR=$(mktemp -d)
CALLS=$(mktemp)
trap 'rm -rf "$SHIMS" "$RESULTS_DIR" "$CALLS"' EXIT
export RESULTS_DIR CALLS

cat >"$SHIMS/aws" <<'SHIM'
#!/usr/bin/env bash
echo "aws $*" >>"$CALLS"
case "$*" in
  *describe-instance-type-offerings*) printf 'ap-southeast-1a\tc7gn.2xlarge\n' ;;
  *describe-instance-types*) echo arm64 ;;
  *get-parameter*) echo ami-0123456789abcdef0 ;;
  *describe-vpcs*) echo vpc-0123 ;;
  *describe-subnets*) echo subnet-0123 ;;
  *create-key-pair*) echo "-----BEGIN OPENSSH PRIVATE KEY-----" ;;
  *create-security-group*) echo sg-0123 ;;
  *run-instances*) printf 'i-0aaa\ti-0bbb\n' ;;
  *describe-instances*) printf '198.51.100.7\t10.0.0.7\n' ;;
esac
SHIM
for tool in ssh scp; do
  cat >"$SHIMS/$tool" <<'SHIM'
#!/usr/bin/env bash
echo "$(basename "$0") $*" >>"$CALLS"
if [[ $FAIL_AT != none && "$*" == *"$FAIL_AT"* ]]; then exit 1; fi
echo '{}'
SHIM
done
cat >"$SHIMS/curl" <<'SHIM'
#!/usr/bin/env bash
echo "curl $*" >>"$CALLS"
echo 203.0.113.7
SHIM
chmod +x "$SHIMS"/*
export PATH="$SHIMS:$PATH"

# Prints the script's exit code. CALLS is truncated here, not in the caller's subshell.
run_case() {
  : >"$CALLS"
  FAIL_AT=$1 AWS_REGION=ap-southeast-1 ../s3-ena-probe.sh --types c7gn.2xlarge >/dev/null 2>&1 \
    && echo 0 || echo $?
}

expect_teardown() {
  local c
  for c in terminate-instances delete-security-group delete-placement-group delete-key-pair; do
    grep -q "$c" "$CALLS" || { echo "FAIL ($1): no $c"; exit 1; }
  done
  # The security group cannot be deleted while instances still use it.
  local term sg
  term=$(grep -n terminate-instances "$CALLS" | head -1 | cut -d: -f1)
  sg=$(grep -n delete-security-group "$CALLS" | head -1 | cut -d: -f1)
  ((term < sg)) || { echo "FAIL ($1): security group deleted before instances"; exit 1; }
}

rc=$(run_case none)
[[ $rc == 0 ]] || { echo "FAIL (success case): exit $rc"; exit 1; }
expect_teardown "success case"
ls "$RESULTS_DIR"/c7gn.2xlarge-*.json >/dev/null || { echo "FAIL: no results file"; exit 1; }

rc=$(run_case run-probe)
[[ $rc != 0 ]] || { echo "FAIL (failure case): exit 0 after a failed step"; exit 1; }
expect_teardown "failure case"

echo PASS
