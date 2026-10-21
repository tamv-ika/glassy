#!/usr/bin/env bash
# S3 spike: measures what XDP/AF_XDP can do on ENA (spec §11 S3). For each instance type it
# launches a DUT and a load generator in a cluster placement group, runs cap-probe on the DUT,
# reflects 64-byte UDP with xdp_reflect.o while the generator floods it, and saves the results
# to results/<type>-<UTC timestamp>.json. Every resource is deleted on exit, even on failure.
#
# Usage: AWS_REGION=<region> bench/aws/s3-ena-probe.sh [--dry-run] [--types "t1 t2"]
#
# THROWAWAY: SP0 benchmark tooling.
set -euo pipefail

: "${AWS_REGION:?set AWS_REGION, e.g. AWS_REGION=ap-southeast-1}"
export AWS_REGION

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
RESULTS_DIR=${RESULTS_DIR:-$HERE/results}
TYPES="c7gn.2xlarge c6in.2xlarge"
DRY_RUN=0
MEASURE_SECS=30
# Instances power off (and so terminate) on their own after this long, in case teardown never
# runs because the shell running this script dies.
SELF_DESTRUCT_MINUTES=120

while (($#)); do
  case $1 in
    --dry-run) DRY_RUN=1 ;;
    --types)
      TYPES=${2:?--types needs a value}
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift
done

RUN_ID=glassy-s3-$(date -u +%Y%m%d%H%M%S)
WORK=$(mktemp -d)

# Everything teardown must delete. Each ID is appended the moment it exists.
INSTANCE_IDS=()
PLACEMENT_GROUPS=()
SG_ID=""
KEY_NAME=""

log() { echo "[s3-ena-probe] $*" >&2; }

# In dry-run mode AWS calls are printed instead of run, and return placeholder values.
aws_() {
  if ((DRY_RUN)); then
    echo "aws $*" >&2
    case "$*" in
      *describe-instance-type-offerings*)
        local t
        for t in $TYPES; do printf '%s-dryrun-az\t%s\n' "$AWS_REGION" "$t"; done
        ;;
      *describe-instance-types*) echo x86_64 ;;
      *get-parameter*) echo ami-dryrun ;;
      *describe-vpcs*) echo vpc-dryrun ;;
      *describe-subnets*) echo subnet-dryrun ;;
      *create-key-pair*) echo dryrun-key ;;
      *create-security-group*) echo sg-dryrun ;;
      *run-instances*) printf 'i-dryrun-dut\ti-dryrun-gen\n' ;;
      *describe-instances*) printf '203.0.113.10\t10.0.0.10\n' ;;
    esac
    return 0
  fi
  aws "$@"
}

ssh_() {
  local host=$1
  shift
  if ((DRY_RUN)); then
    echo "ssh ec2-user@$host $*" >&2
    echo '{}'
    return 0
  fi
  ssh -n -i "$WORK/key.pem" -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="$WORK/known_hosts" -o ConnectTimeout=15 -o ServerAliveInterval=15 \
    "ec2-user@$host" "$@"
}

scp_() {
  if ((DRY_RUN)); then
    echo "scp $*" >&2
    return 0
  fi
  scp -q -i "$WORK/key.pem" -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="$WORK/known_hosts" -o ConnectTimeout=15 "$@"
}

# Runs "$@" up to $1 times, 10s apart; for deletions that race with instance shutdown.
retry() {
  local n=$1
  shift
  local i
  for ((i = 1; i <= n; i++)); do
    "$@" && return 0
    ((i < n)) && ((DRY_RUN == 0)) && sleep 10
  done
  return 1
}

teardown() {
  local rc=$?
  set +e
  trap - EXIT
  log "tearing down $RUN_ID"
  if ((${#INSTANCE_IDS[@]})); then
    aws_ ec2 terminate-instances --instance-ids "${INSTANCE_IDS[@]}" >/dev/null
    aws_ ec2 wait instance-terminated --instance-ids "${INSTANCE_IDS[@]}"
  fi
  if [[ -n $SG_ID ]]; then
    retry 12 aws_ ec2 delete-security-group --group-id "$SG_ID"
  fi
  local pg
  for pg in "${PLACEMENT_GROUPS[@]}"; do
    retry 6 aws_ ec2 delete-placement-group --group-name "$pg"
  done
  if [[ -n $KEY_NAME ]]; then
    aws_ ec2 delete-key-pair --key-name "$KEY_NAME"
  fi
  rm -rf "$WORK"
  if ((rc)); then
    log "FAILED (exit $rc). Resources tagged glassy-run=$RUN_ID were deleted;"
    log "if this shell was cut off, check for leftovers with that tag (see README)."
  fi
  exit "$rc"
}
trap teardown EXIT
# Turn signals into a normal exit so the EXIT trap tears down (HUP: the CloudShell tab closed).
trap 'exit 129' HUP
trap 'exit 130' INT TERM

tag_spec() {
  echo "ResourceType=$1,Tags=[{Key=Name,Value=$RUN_ID},{Key=glassy-run,Value=$RUN_ID}]"
}

# 1. An AZ that offers every requested type.
n_types=$(wc -w <<<"$TYPES")
AZ=$(aws_ ec2 describe-instance-type-offerings --location-type availability-zone \
  --filters "Name=instance-type,Values=${TYPES// /,}" \
  --query 'InstanceTypeOfferings[].[Location,InstanceType]' --output text |
  awk -v n="$n_types" '{c[$1]++} END {for (a in c) if (c[a] == n) print a}' | sort | head -1)
[[ -n $AZ ]] || { log "no AZ in $AWS_REGION offers all of: $TYPES"; exit 1; }
VPC_ID=$(aws_ ec2 describe-vpcs --filters Name=is-default,Values=true \
  --query 'Vpcs[0].VpcId' --output text)
SUBNET_ID=$(aws_ ec2 describe-subnets \
  --filters "Name=availability-zone,Values=$AZ" Name=default-for-az,Values=true \
  --query 'Subnets[0].SubnetId' --output text)
log "run $RUN_ID in $AZ ($VPC_ID / $SUBNET_ID)"

# 2-3. Temporary key pair and security group (shared by all types).
aws_ ec2 create-key-pair --key-name "$RUN_ID" --key-type ed25519 \
  --tag-specifications "$(tag_spec key-pair)" --query KeyMaterial --output text >"$WORK/key.pem"
KEY_NAME=$RUN_ID
chmod 600 "$WORK/key.pem"

SG_ID=$(aws_ ec2 create-security-group --group-name "$RUN_ID" \
  --description "glassy S3 probe (temporary)" --vpc-id "$VPC_ID" \
  --tag-specifications "$(tag_spec security-group)" --query GroupId --output text)
if ((DRY_RUN)); then
  CALLER_IP=198.51.100.1
else
  CALLER_IP=$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')
fi
aws_ ec2 authorize-security-group-ingress --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr "$CALLER_IP/32" >/dev/null
aws_ ec2 authorize-security-group-ingress --group-id "$SG_ID" \
  --ip-permissions "IpProtocol=udp,FromPort=0,ToPort=65535,UserIdGroupPairs=[{GroupId=$SG_ID}]" \
  >/dev/null

# What gets copied to each instance: cap-probe sources and the remote driver.
tar czf "$WORK/glassy.tgz" -C "$REPO/spikes" --exclude=target --exclude='*.o' cap-probe \
  -C "$HERE/remote" run-probe.sh

((DRY_RUN)) || mkdir -p "$RESULTS_DIR"

probe_type() {
  local type=$1
  local arch ami pg launched ids dut gen addrs dut_pub dut_priv gen_pub gen_priv
  arch=$(aws_ ec2 describe-instance-types --instance-types "$type" \
    --query 'InstanceTypes[0].ProcessorInfo.SupportedArchitectures[0]' --output text)
  ami=$(aws_ ssm get-parameter \
    --name "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.12-$arch" \
    --query Parameter.Value --output text)

  # One cluster placement group per type: mixing families in one group often lacks capacity.
  pg="$RUN_ID-${type//./-}"
  aws_ ec2 create-placement-group --group-name "$pg" --strategy cluster \
    --tag-specifications "$(tag_spec placement-group)" >/dev/null
  PLACEMENT_GROUPS+=("$pg")

  # 4. DUT and generator.
  log "$type: launching 2 instances ($ami)"
  # Plain assignments (not read <<<"$(...)") so a failing aws call stops the script.
  launched=$(aws_ ec2 run-instances --image-id "$ami" --instance-type "$type" \
    --count 2 --key-name "$KEY_NAME" --security-group-ids "$SG_ID" --subnet-id "$SUBNET_ID" \
    --placement "GroupName=$pg" --instance-initiated-shutdown-behavior terminate \
    --user-data "#!/bin/bash
shutdown -h +$SELF_DESTRUCT_MINUTES" \
    --tag-specifications "$(tag_spec instance)" \
    --query 'Instances[].InstanceId' --output text)
  read -r -a ids <<<"$launched"
  INSTANCE_IDS+=("${ids[@]}")
  dut=${ids[0]}
  gen=${ids[1]}
  aws_ ec2 wait instance-status-ok --instance-ids "$dut" "$gen"
  addrs=$(aws_ ec2 describe-instances --instance-ids "$dut" \
    --query 'Reservations[0].Instances[0].[PublicIpAddress,PrivateIpAddress]' --output text)
  read -r dut_pub dut_priv <<<"$addrs"
  addrs=$(aws_ ec2 describe-instances --instance-ids "$gen" \
    --query 'Reservations[0].Instances[0].[PublicIpAddress,PrivateIpAddress]' --output text)
  read -r gen_pub gen_priv <<<"$addrs"
  log "$type: DUT $dut_pub ($dut_priv), GEN $gen_pub ($gen_priv)"

  # 5. Ship and build cap-probe on both.
  local host
  for host in "$dut_pub" "$gen_pub"; do
    scp_ "$WORK/glassy.tgz" "ec2-user@$host:glassy.tgz"
    ssh_ "$host" 'mkdir -p glassy && tar xzf glassy.tgz -C glassy' >/dev/null
    ssh_ "$host" ./glassy/run-probe.sh setup >&2
  done

  # 6. Capabilities, as booted and after preparing the NIC for native XDP.
  local probe reflect measure generator
  probe=$(ssh_ "$dut_pub" ./glassy/run-probe.sh probe)

  # 7. Reflect while the generator floods UDP port 9; measure on the DUT in the middle.
  reflect=$(ssh_ "$dut_pub" ./glassy/run-probe.sh reflect-on)
  ssh_ "$gen_pub" ./glassy/run-probe.sh pktgen "$dut_priv" $((MEASURE_SECS + 6)) \
    >"$WORK/generator.json" &
  local gen_pid=$!
  ((DRY_RUN)) || sleep 3
  measure=$(ssh_ "$dut_pub" ./glassy/run-probe.sh measure "$MEASURE_SECS")
  wait "$gen_pid"
  generator=$(cat "$WORK/generator.json")
  ssh_ "$dut_pub" ./glassy/run-probe.sh reflect-off >/dev/null
  # Free this type's vCPU quota before the next type launches; teardown terminates again
  # (a no-op) and waits for it.
  aws_ ec2 terminate-instances --instance-ids "${ids[@]}" >/dev/null

  # 8. Save the result locally.
  local out
  out="$RESULTS_DIR/$type-$(date -u +%Y%m%dT%H%M%SZ).json"
  if ((DRY_RUN)); then
    log "$type: would write $out"
    return 0
  fi
  jq -n --arg type "$type" --arg az "$AZ" --arg ami "$ami" --arg run "$RUN_ID" \
    --argjson probe "$probe" --argjson reflect "$reflect" --argjson measure "$measure" \
    --argjson generator "$generator" \
    '{instance_type: $type, az: $az, ami: $ami, run_id: $run, probe: $probe,
      reflect: $reflect, reflector: $measure, generator: $generator}' >"$out"
  log "$type: wrote $out"
}

for type in $TYPES; do
  probe_type "$type"
done
log "done"
