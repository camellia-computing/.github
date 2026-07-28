#!/usr/bin/env bash
set -euo pipefail

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
fake_bin="$root/bin"
log="$root/gh.log"
report_json="$root/audit-report.json"
report_markdown="$root/audit-report.md"
mkdir -p "$fake_bin" "$root/runner"

cat > "$fake_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${GH_TOKEN:-}" == test-token ]]
if [[ "$1" == issue && "$2" == list ]]; then
  printf '%s\n' "$FAKE_ISSUES"
else
  printf '%s\n' "$*" >> "$FAKE_GH_LOG"
fi
EOF
chmod +x "$fake_bin/gh"

write_report() {
  local status="$1" count=0
  [[ "$status" == drift ]] && count=1
  jq -n \
    --arg status "$status" \
    --argjson count "$count" '{
      schema_version: 1,
      policy_revision: "2026-07-28.1",
      status: $status,
      drift_count: $count,
      drifts: (if $count == 0 then [] else [{control: "fixture"}] end)
    }' > "$report_json"
  printf '# Fixture audit\n' > "$report_markdown"
}

run_reconcile() {
  local outcome="$1" issues="$2"
  PATH="$fake_bin:$PATH" \
  AUDIT_ISSUE_REPOSITORY=test/repository \
  AUDIT_OUTCOME="$outcome" \
  AUDIT_REPORT_JSON="$report_json" \
  AUDIT_REPORT_MARKDOWN="$report_markdown" \
  FAKE_GH_LOG="$log" \
  FAKE_ISSUES="$issues" \
  GH_TOKEN=test-token \
  RUNNER_TEMP="$root/runner" \
    bash scripts/reconcile_policy_audit_issue.sh
}

write_report drift
: > "$log"
run_reconcile failure '[]'
grep -Fq 'label create policy-drift' "$log"
grep -Fq 'issue create' "$log"

: > "$log"
run_reconcile failure '[{"number":17,"title":"[automation] Repository policy drift"}]'
grep -Fq 'issue edit 17' "$log"
if grep -Fq 'issue create' "$log"; then
  echo 'Existing drift issue was duplicated' >&2
  exit 1
fi

write_report compliant
: > "$log"
run_reconcile success '[{"number":17,"title":"[automation] Repository policy drift"}]'
grep -Fq 'issue close 17' "$log"

: > "$log"
run_reconcile success '[]'
[[ ! -s "$log" ]]

if run_reconcile success '[
  {"number":17,"title":"[automation] Repository policy drift"},
  {"number":18,"title":"[automation] Repository policy drift"}
]' >/dev/null 2>&1; then
  echo 'Duplicate drift issues were accepted' >&2
  exit 1
fi

echo 'Repository policy issue reconciliation tests passed'
