#!/usr/bin/env bash
# Runs user-role-inventory.sh against the mock az CLI in tests/mock and checks the reports.
# Needs only bash and jq - no Azure access.
# SPDX-License-Identifier: MIT
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../user-role-inventory.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export PATH="$HERE/mock:$PATH"
export MOCK_CALLS="$WORK/calls"

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }
# col <file> <key column> <key value> <column header> -> values of matching rows, joined by |
col() {
  awk -F'\t' -v k="$2" -v v="$3" -v h="$4" 'NR == 1 {for (i = 1; i <= NF; i++) {if ($i == k) kc = i; if ($i == h) hc = i}; next}
    $kc == v {printf "%s%s", (n++ ? "|" : ""), $hc} END {print ""}' "$1"
}
is() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got '$2', expected '$3')"; fi; }
rows() { echo $(($(wc -l < "$1") - 1)); }

echo "whole tenant"
O="$WORK/full"
if bash "$SCRIPT" -o "$O" 2>"$WORK/log"; then ok "exits 0"; else bad "exits 0"; cat "$WORK/log"; fi
is "4 users with roles (users over two Graph pages)"    "$(rows "$O/users.tsv")" 4
is "synced admin with MG Owner -> CRITICAL"             "$(col "$O/users.tsv" name alice risk)" CRITICAL
is "  ... concerns"                                     "$(col "$O/users.tsv" name alice concern)" "group synced from on-prem; synced account"
is "  ... MG Owner counted once (case-insensitive dedupe)" "$(col "$O/users.tsv" name alice azureRoles)" 3
is "  ... Entra role through role-assignable group"     "$(awk -F'\t' '$3=="alice" && $6=="Entra" {print $7" "$11}' "$O/assignments.tsv")" "Application Administrator group: g-app-admins"
is "cloud-only Global Admin -> CRITICAL, not synced"    "$(col "$O/users.tsv" name bob risk)/$(col "$O/users.tsv" name bob synced)" CRITICAL/no
is "disabled synced user with roles flagged"            "$(col "$O/users.tsv" name carol concern)" "disabled account; group synced from on-prem; synced account"
is "subscription Owner -> HIGH"                         "$(col "$O/users.tsv" name carol risk)" HIGH
is "Reader through synced group -> LOW"                 "$(col "$O/users.tsv" name dave risk)" LOW
is "user without roles not listed"                      "$(col "$O/users.tsv" name eve risk)" ""
is "service principal members ignored"                  "$(grep -c sp1 "$O/assignments.tsv")" 0
is "synced groups with roles"                           "$(cut -f2 "$O/synced_groups.tsv" | tail -n +2 | tr '\n' ' ')" "g-onprem-admins g-all-staff "
is "  ... member count"                                 "$(col "$O/synced_groups.tsv" group g-onprem-admins userMembers)" 2
is "cloud-only group not in synced_groups"              "$(grep -c g-app-admins "$O/synced_groups.tsv")" 0
if grep -q "root scope (/) role assignments not readable" "$WORK/log"; then ok "root scope refusal reported"; else bad "root scope refusal reported"; fi
if ! grep -q roleEligibilitySchedule "$MOCK_CALLS"; then ok "no PIM calls without -E"; else bad "no PIM calls without -E"; fi
if [[ ! -e "$O/user_groups.tsv" ]]; then ok "no user_groups.tsv without -u"; else bad "no user_groups.tsv without -u"; fi
perm=$(stat -c %a "$O/users.tsv" 2>/dev/null || stat -f %Lp "$O/users.tsv")
is "reports readable by owner only"                     "$perm" 600

echo "-u (one user)"
U="$WORK/u"
bash "$SCRIPT" -u alice@contoso.test -o "$U" 2>/dev/null
is "only that user"                                     "$(rows "$U/users.tsv")" 1
is "all 3 groups, newest first"                         "$(cut -f2 "$U/user_groups.tsv" | tail -n +2 | tr '\n' ' ')" "g-app-admins g-onprem-admins g-all-staff "
is "direct vs nested"                                   "$(cut -f4 "$U/user_groups.tsv" | tail -n +2 | tr '\n' ' ')" "direct direct nested "
is "group owner listed"                                 "$(col "$U/user_groups.tsv" group g-app-admins owners)" bob@contoso.test
is "roles held by the group"                            "$(col "$U/user_groups.tsv" group g-onprem-admins rolesHeld)" "Contributor @ /subscriptions/11111111-0000-0000-0000-000000000001"
is "dynamic group type"                                 "$(col "$U/user_groups.tsv" group g-all-staff type)" "security (dynamic)"
is "tab in description replaced"                        "$(col "$U/user_groups.tsv" group g-all-staff description)" "all staff"
is "same roles as in the whole-tenant run"              "$(col "$U/users.tsv" name alice privilegedRoles)" "$(col "$O/users.tsv" name alice privilegedRoles)"
if ! bash "$SCRIPT" -u nobody@contoso.test -o "$WORK/nobody" >/dev/null 2>&1; then ok "unknown user fails"; else bad "unknown user fails"; fi

echo "-E (PIM-eligible Azure roles)"
bash "$SCRIPT" -E -o "$WORK/e" 2>/dev/null
is "eligible MG Contributor -> CRITICAL"                "$(col "$WORK/e/users.tsv" name dave risk)" CRITICAL
is "  ... marked eligible"                              "$(col "$WORK/e/users.tsv" name dave privilegedRoles)" "Contributor @ managementGroup (eligible)"

echo "Windows (Git Bash: CRLF output from az and jq, MSYS path rewriting)"
REAL_JQ=$(type -P jq) PATH="$HERE/mock-windows:$PATH" bash "$SCRIPT" -o "$WORK/win" 2>"$WORK/winlog"
if grep -q "Bad Request" "$WORK/winlog"; then
  bad "no 'Bad Request' errors"; grep -m3 "Bad Request" "$WORK/winlog"
else ok "no 'Bad Request' errors"; fi
for f in users assignments synced_groups; do
  if cmp -s "$O/$f.tsv" "$WORK/win/$f.tsv"; then ok "$f.tsv same as on Linux"; else bad "$f.tsv same as on Linux"; fi
done

echo "argument checks"
if ! bash "$SCRIPT" -u 'bad user;' >/dev/null 2>&1; then ok "rejects a malformed user"; else bad "rejects a malformed user"; fi
if bash "$SCRIPT" -h | grep -q "READ-ONLY inventory"; then ok "-h prints help"; else bad "-h prints help"; fi

echo
echo "$pass passed, $fail failed"
((fail == 0))
