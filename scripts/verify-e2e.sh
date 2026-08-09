#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  printf 'e2e: root is required\n'
  exit 1
fi

for tool in go ip getent useradd userdel groupdel mktemp; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'e2e: required tool is missing: %s\n' "${tool}" >&2
    exit 1
  fi
done

if [[ ${1:-} == '--preflight-only' ]]; then
  if [[ $# -ne 1 ]]; then
    printf 'e2e: --preflight-only accepts no arguments\n' >&2
    exit 1
  fi
  printf 'e2e: preflight passed\n'
  exit 0
fi
if [[ $# -ne 0 ]]; then
  printf 'e2e: unexpected arguments\n' >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d /var/tmp/claude-egress-proxy-e2e.XXXXXXXX)"
namespace="cep-e2e-$$-${RANDOM}"
service_user='claude-egress-proxy'
created_user=0
namespace_created=0

cleanup() {
  local original_status=$?
  local cleanup_failed=0
  local pid
  local -a pids=()
  trap - EXIT INT TERM

  if [[ ${namespace_created} -eq 1 ]]; then
    mapfile -t pids < <(ip netns pids "${namespace}" 2>/dev/null || true)
    if [[ ${#pids[@]} -gt 0 ]]; then
      cleanup_failed=1
      kill -TERM "${pids[@]}" 2>/dev/null || true
      for _ in {1..20}; do
        mapfile -t pids < <(ip netns pids "${namespace}" 2>/dev/null || true)
        [[ ${#pids[@]} -eq 0 ]] && break
        sleep 0.1
      done
      if [[ ${#pids[@]} -gt 0 ]]; then
        kill -KILL "${pids[@]}" 2>/dev/null || true
      fi
    fi
    ip netns delete "${namespace}" >/dev/null 2>&1 || cleanup_failed=1
  fi

  case "${work}" in
    /var/tmp/claude-egress-proxy-e2e.*)
      rm -rf -- "${work}" || cleanup_failed=1
      ;;
    *)
      printf 'e2e: refused unsafe cleanup path: %s\n' "${work}" >&2
      cleanup_failed=1
      ;;
  esac

  if [[ ${created_user} -eq 1 ]]; then
    userdel "${service_user}" >/dev/null 2>&1 || cleanup_failed=1
    if getent group "${service_user}" >/dev/null 2>&1; then
      groupdel "${service_user}" >/dev/null 2>&1 || cleanup_failed=1
    fi
  fi

  if [[ ${cleanup_failed} -ne 0 ]]; then
    printf 'e2e: cleanup failed\n' >&2
    exit 1
  fi
  exit "${original_status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

chmod 0755 "${work}"
mkdir -p "${work}/bin" "${work}/test" "${work}/runtime"
chmod 0755 "${work}/bin" "${work}/test" "${work}/runtime"

if ! getent passwd "${service_user}" >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "${service_user}"
  created_user=1
fi

cd "${repo_root}"
go mod download
CGO_ENABLED=0 go build -trimpath -o "${work}/bin/claude-egress-proxy" ./cmd/claude-egress-proxy
go test -c -o "${work}/test/e2e.test" ./integration/e2e
chmod 0755 "${work}/bin/claude-egress-proxy" "${work}/test/e2e.test"

ip netns add "${namespace}"
namespace_created=1
ip -n "${namespace}" link set lo up
ip -n "${namespace}" address add 192.0.0.9/32 dev lo
ip -n "${namespace}" address add 192.0.0.10/32 dev lo

set +e
ip netns exec "${namespace}" env \
  CEP_E2E_BINARY="${work}/bin/claude-egress-proxy" \
  CEP_E2E_WORK_ROOT="${work}/runtime" \
  "${work}/test/e2e.test" '-test.run=^TestProductionBinaryE2E$' '-test.v=true' \
  >"${work}/e2e.log" 2>&1
test_status=$?
set -e

if [[ ${test_status} -ne 0 ]]; then
  failure_dir="${repo_root}/out/e2e"
  failure_log="${failure_dir}/failure-$(date -u +%Y%m%dT%H%M%SZ)-$$.log"
  mkdir -p "${failure_dir}"
  cp "${work}/e2e.log" "${failure_log}"
  cat "${failure_log}" >&2
  exit "${test_status}"
fi

printf 'e2e: production binary passed black-box verification\n'
