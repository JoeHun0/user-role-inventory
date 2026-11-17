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
is "3 users with roles (users over two Graph pages)"    "$(rows "$O/users.tsv")" 3
is "synced admin with MG Owner -> CRITICAL"             "$(col "$O/users.tsv" name alice risk)" CRITICAL
is "  ... concerns"                                     "$(col "$O/users.tsv" name alice concern)" "group synced from on-prem; synced account"
is "  ... MG Owner counted once (case-insensitive dedupe)" "$(col "$O/users.tsv" name alice azureRoles)" 2
is "  ... Entra role through role-assignable group"     "$(awk -F'\t' '$3=="alice" && $6=="Entra" {print $7" "$11}' "$O/assignments.tsv")" "Application Administrator group: g-app-admins"
is "cloud-only Global Admin -> CRITICAL, not synced"    "$(col "$O/users.tsv" name bob risk)/$(col "$O/users.tsv" name bob synced)" CRITICAL/no
is "disabled synced user with roles flagged"            "$(col "$O/users.tsv" name carol concern)" "disabled account; group synced from on-prem; synced account"
is "subscription Owner -> HIGH"                         "$(col "$O/users.tsv" name carol risk)" HIGH
is "Reader through a group: kept at group level, not per member" "$(col "$O/users.tsv" name dave risk)" ""
is "  ... the group is still reported"                  "$(col "$O/synced_groups.tsv" group g-all-staff risk)" LOW
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
is "all 3 groups, newest first"                         "$(cut -f3 "$U/user_groups.tsv" | tail -n +2 | tr '\n' ' ')" "g-app-admins g-onprem-admins g-all-staff "
is "direct vs nested"                                   "$(cut -f5 "$U/user_groups.tsv" | tail -n +2 | tr '\n' ' ')" "direct direct nested "
is "group owner listed"                                 "$(col "$U/user_groups.tsv" group g-app-admins owners)" bob@contoso.test
is "roles held by the group"                            "$(col "$U/user_groups.tsv" group g-onprem-admins rolesHeld)" "Contributor @ /subscriptions/11111111-0000-0000-0000-000000000001"
is "dynamic group type"                                 "$(col "$U/user_groups.tsv" group g-all-staff type)" "security (dynamic)"
is "tab in description replaced"                        "$(col "$U/user_groups.tsv" group g-all-staff description)" "all staff"
is "-u: Reader through a group still shown for one user" "$(col "$U/users.tsv" name alice azureRoles)" 3
is "same roles as in the whole-tenant run"              "$(col "$U/users.tsv" name alice privilegedRoles)" "$(col "$O/users.tsv" name alice privilegedRoles)"
if ! bash "$SCRIPT" -u nobody@contoso.test -o "$WORK/nobody" >/dev/null 2>&1; then ok "unknown user fails"; else bad "unknown user fails"; fi

echo "-E (PIM-eligible Azure roles)"
bash "$SCRIPT" -E -o "$WORK/e" 2>/dev/null
is "eligible MG Contributor -> CRITICAL"                "$(col "$WORK/e/users.tsv" name dave risk)" CRITICAL
is "  ... marked eligible"                              "$(col "$WORK/e/users.tsv" name dave privilegedRoles)" "Contributor @ managementGroup (eligible)"

echo "user-role-summary.sh"
SUM="$HERE/../user-role-summary.sh"
line() { if grep -qF -- "$2" "$3"; then ok "$1"; else bad "$1"; fi; }
bash "$SUM" -o "$WORK/sum" "$WORK/e" 2>"$WORK/sumlog" && ok "summary exits 0" || { bad "summary exits 0"; cat "$WORK/sumlog"; }
R="$WORK/sum/user-role-report.md"; C="$WORK/sum/user-role-worklist.csv"
line "report: users read"          "Users read: **5**, of which synced from on-prem: **3**." "$R"
line "report: risk table"          "| CRITICAL | 3 | 2 | 1 | 0 |" "$R"
line "report: disabled with roles" "Disabled accounts that still hold roles: **1**; with HIGH or CRITICAL roles: **1**" "$R"
line "report: synced group path"   "| through a synced group | 2 | 2 | 0 |" "$R"
line "report: eligible counted"    "| direct | 4 | 3 | 1 |" "$R"
line "report: top roles"           "| Contributor @ subscription [Azure] | 2 | 2 |" "$R"
line "report: concentration"       "| 2-5 | 2 | 2 |" "$R"
line "report: synced groups by risk, highest first" "$(printf '| HIGH | 1 |\n')" "$R"
line "report: worklist counts"     "| CRITICAL | 2 |" "$R"
if ! grep -qE "contoso|alice|carol|g-onprem|11111111|0000000000" "$R"; then ok "report: no names or IDs"; else bad "report: no names or IDs"; fi
if [[ "$(head -c3 "$C" | od -An -tx1 | tr -d ' ')" == efbbbf ]]; then ok "worklist: UTF-8 BOM for Excel"; else bad "worklist: UTF-8 BOM for Excel"; fi
line "worklist: user and group columns" '"item_id","severity","priority","category","issue","action","kind","user_upn"' "$C"
is "worklist: 6 items"             "$(($(wc -l < "$C") - 1))" 6
line "worklist: synced admin"      '"USR-SYNCED-PRIV:00000000-0000-0000-0000-0000000000a1","CRITICAL","1"' "$C"
line "worklist: disabled user"     '"USR-DISABLED-ROLES:00000000-0000-0000-0000-0000000000c1","HIGH","2"' "$C"
line "worklist: synced group"      '"GRP-SYNCED-PRIV:00000000-0000-0000-0000-0000000000f2","HIGH","2"' "$C"
line "worklist: cloud-only CRITICAL review" '"USR-PRIV-REVIEW:00000000-0000-0000-0000-0000000000b1","MEDIUM","3"' "$C"
bash "$SUM" -s ';' "$U" 2>/dev/null
UR="$U/user-role-report.md"; UC="$U/user-role-worklist.csv"
line "-u report: groups"           "Groups: **3**; memberships: 3 (direct: 2, nested: 1)" "$UR"
line "-u report: roles on non-role-assignable groups" "not** role-assignable (owners, Groups Administrators and User Administrators can change membership): **2**" "$UR"
line "-u report: group types"      "| security (dynamic) | 1 |" "$UR"
if ! grep -qE "contoso|alice|g-app|0000000000" "$UR"; then ok "-u report: no names or IDs"; else bad "-u report: no names or IDs"; fi
line "-u worklist: membership item (user:group)" '"USR-GROUP-MEMBERSHIP:00000000-0000-0000-0000-0000000000a1:00000000-0000-0000-0000-0000000000f1";"CRITICAL"' "$UC"
line "-u worklist: recent group item (group only)" '"GRP-RECENT-PRIV:00000000-0000-0000-0000-0000000000f1";"MEDIUM"' "$UC"
if ! bash "$SUM" "$WORK/nonexistent" >/dev/null 2>&1; then ok "rejects a folder without inventory"; else bad "rejects a folder without inventory"; fi

echo "user-role-summary.sh at scale"
mkdir -p "$WORK/big/raw"
jq -c 'range(0; 1500) as $i | . + {user: (.user + {id: "\(.user.id)-\($i)", upn: "\($i)-\(.user.upn)"})}' "$WORK/e/raw/model.jsonl" > "$WORK/big/raw/model.jsonl"
cp "$WORK/e/raw/users.jsonl" "$WORK/big/raw/"; cp "$WORK/e/synced_groups.tsv" "$WORK/big/"
if bash "$SUM" "$WORK/big" >/dev/null 2>"$WORK/biglog"; then ok "6 000 users: no 'argument list too long'"; else bad "6 000 users: no 'argument list too long'"; cat "$WORK/biglog"; fi
is "  ... all items written" "$(($(wc -l < "$WORK/big/user-role-worklist.csv") - 1))" 7501

echo "scale: 10 000 users, a 5 000-member group with Reader on 50 subscriptions"
SD="$WORK/scale"; mkdir -p "$SD"
jq -n -c '{value: [range(0;10000) | {id: "u\(.)", displayName: "u\(.)", userPrincipalName: "u\(.)@contoso.test", accountEnabled: ((. % 9) != 0), onPremisesSyncEnabled: true}]}' > "$SD/users.json"
jq -n -c '{value: [range(0;3000) | {id: "g\(.)", displayName: "g\(.)", onPremisesSyncEnabled: true, isAssignableToRole: false, securityEnabled: true, groupTypes: []}]}' > "$SD/groups.json"
jq -n -c '{value: [range(0;5000) | {"@odata.type": "#microsoft.graph.user", id: "u\(.)"}]}' > "$SD/members-big.json"
jq -n -c '{value: [range(0;20) | {"@odata.type": "#microsoft.graph.user", id: "u\(. * 37)"}]}' > "$SD/members-small.json"
jq -n -c '{data: ([range(0;50) | {id: "/subscriptions/s\(.)/ra/big\(.)", principalId: "g0", roleDefinitionId: "x/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7", scope: "/subscriptions/s\(.)"}]
            + [range(1;101) | {id: "/subscriptions/s\(.)/ra/c\(.)", principalId: "g\(.)", roleDefinitionId: "x/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c", scope: "/subscriptions/s\(.)"}]), skip_token: null}' > "$SD/rbac.json"
echo '{"data":[{"name":"acdd72a7-3385-48ef-bd42-f606fba81ae7","roleName":"Reader"},{"name":"b24988ac-6180-42a0-ab88-20f7382dd24c","roleName":"Contributor"}],"skip_token":null}' > "$SD/roledefs.json"
start=$SECONDS
if MOCK_SCALE_DIR="$SD" PATH="$HERE/mock-scale:$PATH" bash "$SCRIPT" -o "$WORK/scaleout" 2>/dev/null; then ok "scale run exits 0"; else bad "scale run exits 0"; fi
is "Reader through the big group not expanded per member" "$(($(wc -l < "$WORK/scaleout/assignments.tsv") - 1))" 2000
if ((SECONDS - start < 120)); then ok "scale run under 2 minutes ($((SECONDS - start)) s)"; else bad "scale run under 2 minutes ($((SECONDS - start)) s)"; fi
line "  ... big group still reported as a synced group with roles" "$(printf 'LOW\tg0\tg0\t5000\t')" "$WORK/scaleout/synced_groups.tsv"

echo "Windows (Git Bash: CRLF output from az and jq, MSYS path rewriting)"
REAL_JQ=$(type -P jq) PATH="$HERE/mock-windows:$PATH" bash "$SCRIPT" -o "$WORK/win" 2>"$WORK/winlog"
if grep -q "Bad Request" "$WORK/winlog"; then
  bad "no 'Bad Request' errors"; grep -m3 "Bad Request" "$WORK/winlog"
else ok "no 'Bad Request' errors"; fi
for f in users assignments synced_groups; do
  if cmp -s "$O/$f.tsv" "$WORK/win/$f.tsv"; then ok "$f.tsv same as on Linux"; else bad "$f.tsv same as on Linux"; fi
done

echo "several users (-u twice, -U file)"
M2="$WORK/multi"
: > "$MOCK_CALLS"
bash "$SCRIPT" -u alice@contoso.test -u bob@contoso.test -o "$M2" 2>"$WORK/multilog"
is "two users examined"                     "$(rows "$M2/users.tsv")" 2
is "one row per user and group"             "$(rows "$M2/user_groups.tsv")" 4
is "  ... user column"                      "$(cut -f1 "$M2/user_groups.tsv" | tail -n +2 | sort -u | tr '\n' ' ')" "alice@contoso.test bob@contoso.test "
is "shared group: owners read once"         "$(grep -c "groups/00000000-0000-0000-0000-0000000000f1/owners" "$MOCK_CALLS")" 1
bash "$SUM" "$M2" 2>/dev/null
line "report: distinct groups and memberships" "Groups: **3**; memberships: 4 (direct: 3, nested: 1)" "$M2/user-role-report.md"
line "report: per-user row, numbered"       "| user 1 | 3 | 2 |" "$M2/user-role-report.md"
line "report: second user"                  "| user 2 | 1 | 1 |" "$M2/user-role-report.md"
if ! grep -qE "alice|bob|contoso" "$M2/user-role-report.md"; then ok "report: no names"; else bad "report: no names"; fi
is "group item once, though both users are in the group" "$(grep -c '"GRP-RECENT-PRIV:' "$M2/user-role-worklist.csv")" 1
line "membership item for the second user"  '"USR-GROUP-MEMBERSHIP:00000000-0000-0000-0000-0000000000b1:00000000-0000-0000-0000-0000000000f1","CRITICAL"' "$M2/user-role-worklist.csv"
printf '# admins to check\r\nalice@contoso.test\r\n\r\nnobody@contoso.test  # left already\r\nbob@contoso.test\r\n' > "$WORK/users.txt"
bash "$SCRIPT" -U "$WORK/users.txt" -o "$WORK/ufile" 2>"$WORK/ufilelog"
is "-U file: comments, blank lines and CRLF handled" "$(rows "$WORK/ufile/users.tsv")" 2
if grep -q "user not found or not readable: nobody@contoso.test" "$WORK/ufilelog"; then ok "  ... missing user warned, run continues"; else bad "  ... missing user warned, run continues"; fi
if ! bash "$SCRIPT" -u nobody@contoso.test -o "$WORK/none" >/dev/null 2>&1; then ok "no readable user at all: fails"; else bad "no readable user at all: fails"; fi

echo "argument checks"
if ! bash "$SCRIPT" -u 'bad user;' >/dev/null 2>&1; then ok "rejects a malformed user"; else bad "rejects a malformed user"; fi
if bash "$SCRIPT" -h | grep -q "READ-ONLY inventory"; then ok "-h prints help"; else bad "-h prints help"; fi

echo "tenant root access check"
bash "$HERE/../user-role-summary.sh" -o "$WORK/rootok" "$WORK/e" 2>/dev/null
if ! grep -q "incomplete inventory" "$WORK/rootok/user-role-report.md"; then ok "full access: no warning in the report"; else bad "full access: no warning in the report"; fi
MOCK_NO_ROOT=1 bash "$SCRIPT"  -o "$WORK/noroot" 2>"$WORK/norootlog"
if grep -q "can't read the tenant root management group" "$WORK/norootlog"; then ok "no root access: warning on screen"; else bad "no root access: warning on screen"; fi
bash "$HERE/../user-role-summary.sh" "$WORK/noroot" 2>/dev/null
if grep -q "Warning: incomplete inventory" "$WORK/noroot/user-role-report.md"; then ok "no root access: warning in the report"; else bad "no root access: warning in the report"; fi

echo "portability"
if ! (cd "$HERE/.." && grep -nE '(fromdateiso8601|fromdate|strptime|mktime|strftime|todate|dateadd)\b' user-role-inventory.sh user-role-summary.sh | grep -v '^[^:]*:[0-9]*:[[:space:]]*#'); then
  ok "no jq date built-ins (missing in some Windows jq builds)"
else bad "no jq date built-ins (missing in some Windows jq builds)"; fi
# variables named after a keyword, or keywords as shorthand object keys
KWPAT='[$](as|if|then|elif|else|end|and|or|not|def|reduce|foreach|try|catch|label|import|include)\b|[{,][[:space:]]*(as|if|then|elif|else|end|and|or|not|def|reduce|foreach|try|catch|label|import|include)[[:space:]]*[,}]'
if ! (cd "$HERE/.." && grep -nE "$KWPAT" user-role-inventory.sh user-role-summary.sh | grep -v '^[^:]*:[0-9]*:[[:space:]]*#' | grep -v 'APP_QUERY='); then
  ok "no jq keywords as variable names or object keys (rejected by jq 1.6)"
else bad "no jq keywords as variable names or object keys (rejected by jq 1.6)"; fi
echo
echo "$pass passed, $fail failed"
((fail == 0))
