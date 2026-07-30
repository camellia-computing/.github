#!/usr/bin/env bash
set -euo pipefail

: "${AUDIT_OUTCOME:?AUDIT_OUTCOME is required}"
: "${AUDIT_REPORT_JSON:?AUDIT_REPORT_JSON is required}"
: "${AUDIT_REPORT_MARKDOWN:?AUDIT_REPORT_MARKDOWN is required}"
: "${AUDIT_ISSUE_REPOSITORY:?AUDIT_ISSUE_REPOSITORY is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

[[ "$AUDIT_OUTCOME" == success || "$AUDIT_OUTCOME" == failure ]] || {
  echo "Unsupported audit outcome: $AUDIT_OUTCOME" >&2
  exit 2
}
[[ -f "$AUDIT_REPORT_JSON" && -f "$AUDIT_REPORT_MARKDOWN" ]] || {
  echo 'Audit reports are unavailable' >&2
  exit 2
}

expected_status=compliant
[[ "$AUDIT_OUTCOME" == failure ]] && expected_status=drift
jq -e \
  --arg status "$expected_status" \
  '.schema_version == 2 and .status == $status and
   (.drift_count | type == "number") and (.drifts | type == "array")' \
  "$AUDIT_REPORT_JSON" >/dev/null || {
  echo 'Audit report does not match the workflow outcome' >&2
  exit 2
}

issue_title='[automation] Repository policy drift'
issues_json="$(
  gh issue list \
    --json number,title \
    --label policy-drift \
    --limit 100 \
    --repo "$AUDIT_ISSUE_REPOSITORY" \
    --state open
)"
mapfile -t issue_numbers < <(
  jq -r --arg title "$issue_title" \
    '.[] | select(.title == $title) | .number' <<< "$issues_json"
)
((${#issue_numbers[@]} <= 1)) || {
  echo 'Multiple open repository policy drift issues require manual reconciliation' >&2
  exit 1
}

if [[ "$AUDIT_OUTCOME" == success ]]; then
  if ((${#issue_numbers[@]} == 1)); then
    revision="$(jq -r '.policy_revision' "$AUDIT_REPORT_JSON")"
    gh issue close "${issue_numbers[0]}" \
      --comment "Automated audit revision \`$revision\` is compliant; closing the resolved drift record." \
      --repo "$AUDIT_ISSUE_REPOSITORY"
  else
    echo 'Repository policy is compliant and no drift issue is open'
  fi
  exit 0
fi

gh label create policy-drift \
  --color B60205 \
  --description 'Automated repository policy audit drift' \
  --force \
  --repo "$AUDIT_ISSUE_REPOSITORY"

issue_body="$(mktemp "$RUNNER_TEMP/camellia-policy-audit-issue.XXXXXX")"
trap 'rm -f "$issue_body"' EXIT
{
  cat "$AUDIT_REPORT_MARKDOWN"
  printf '\n<!-- camellia-policy-audit -->\n'
  printf 'This issue is reconciled by the organization policy audit workflow.\n'
} > "$issue_body"

if ((${#issue_numbers[@]} == 0)); then
  gh issue create \
    --body-file "$issue_body" \
    --label policy-drift \
    --repo "$AUDIT_ISSUE_REPOSITORY" \
    --title "$issue_title"
else
  gh issue edit "${issue_numbers[0]}" \
    --add-label policy-drift \
    --body-file "$issue_body" \
    --repo "$AUDIT_ISSUE_REPOSITORY"
fi
