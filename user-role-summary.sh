#!/usr/bin/env bash
# user-role-summary.sh - turns a user-role-inventory output folder into two files:
#
#   user-role-report.md     counts only, no user, group or scope names - safe to put into
#                           a report: users per risk level, synced and disabled accounts
#                           with roles, how privileged access is held, the most common
#                           privileged roles, privilege concentration, synced groups with
#                           roles; for a -u folder also the user's groups by type, age,
#                           owners and roles held
#   user-role-worklist.csv  one row per thing to fix (users and groups), with names,
#                           details and what to do - internal. item_id (category:object ID)
#                           stays the same between runs, so the file can feed a tracking
#                           spreadsheet (Excel: Data > From Text/CSV) and statuses kept
#                           there survive a refresh.
#
# Usage:
#   ./user-role-summary.sh <output folder>           writes both files into that folder
#   ./user-role-summary.sh -o <dir> <output folder>  writes them into <dir> instead
#   ./user-role-summary.sh -s ';' <output folder>    CSV separator (default ","; use ";" if
#                                                    Excel with a Hungarian or German locale
#                                                    opens it)
#
# Reads raw/model.jsonl, raw/users.jsonl, synced_groups.tsv and (if present)
# user_groups.tsv from the folder. Needs only jq; no Azure access.

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Kotnyek József
# https://github.com/JoeHun0/user-role-inventory

set -uo pipefail

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; }

SEP=","
OUT=""
while getopts ":s:o:h" opt; do
  case "$opt" in
    s) SEP="$OPTARG" ;;
    o) OUT="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) echo "Unknown option. Use -h for help." >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
(($# == 1)) || die "give one user-role-inventory output folder (-h for help)"
[[ "$SEP" == "," || "$SEP" == ";" || "$SEP" == $'\t' ]] || die "-s must be , or ; or a tab"
DIR="$1"
[[ -f "$DIR/raw/model.jsonl" && -s "$DIR/raw/users.jsonl" && -s "$DIR/synced_groups.tsv" ]] \
  || die "raw/model.jsonl, raw/users.jsonl or synced_groups.tsv not found in $DIR - is this a user-role-inventory output folder?"
command -v jq >/dev/null || die "jq not found (sudo apt install jq)"
jq() { command jq "$@" | tr -d '\r'; }   # Windows jq ends lines with CRLF

OUT=${OUT:-$DIR}
umask 077
mkdir -p "$OUT" || die "cannot create $OUT"
DETECTED=$(date -r "$DIR/raw/model.jsonl" +%Y-%m-%d 2>/dev/null || date +%Y-%m-%d)
UG="$DIR/user_groups.tsv"
[[ -s "$UG" ]] || UG=/dev/null

# ---------------------------------------------------------------- shared jq
read -r -d '' JQ_PRE <<'JQ'
def risklabel: ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][.];
def riskvalue: {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[.] // 0;
def cnt(f): map(select(f)) | length;
def tsv: split("\n") | map(select(length > 0) | split("\t"))
         | if length == 0 then [] else .[0] as $h | [.[1:][] | [$h, .] | transpose | map({key: .[0], value: .[1]}) | from_entries] end;
def ts: # ISO 8601 date -> Unix seconds (UTC), in plain arithmetic: some Windows builds of
         # jq have no strptime, so the built-in ISO date parser fails there
  if . == null or . == "" then null
  else (capture("^(?<y>[0-9]{4})-(?<mo>[0-9]{2})-(?<d>[0-9]{2})([T ](?<h>[0-9]{2}):(?<mi>[0-9]{2})(:(?<s>[0-9]{2}))?)?") // null) as $c
  | if $c == null then null
    else ($c.mo | tonumber) as $m
    | (($c.y | tonumber) - (if $m <= 2 then 1 else 0 end)) as $y
    | (($y / 400) | floor) as $era | ($y - $era * 400) as $yoe
    | (((153 * (if $m > 2 then $m - 3 else $m + 9 end) + 2) / 5 | floor) + ($c.d | tonumber) - 1) as $doy
    | ($era * 146097 + $yoe * 365 + ($yoe / 4 | floor) - ($yoe / 100 | floor) + $doy - 719468) * 86400
      + (($c.h // "0") | tonumber) * 3600 + (($c.mi // "0") | tonumber) * 60 + (($c.s // "0") | tonumber)
    end
  end;
def rlabel: "\(.role) @ \(.level) [\(if .src == "entra" then "Entra" else "Azure" end)]";
def how: if .via == "direct" then "direct"
         elif .group.synced then "through a synced group"
         else "through a cloud group" end;
def adminname: test("admin|adm\\b|owner|privileged|security|global|contributor|operator"; "i");

($sg | tsv) as $SG
| ($ug | tsv | map(. + {age: ((now - (.created | ts // now)) / 86400)})) as $UG
| ($UG | length > 0) as $single
| $m as $M
| ($M | group_by(.user.id) | map({u: .[0].user, rating: (map(.rating) | max), rows: .,
                                   priv: (map(select(.rating >= 3) | rlabel) | unique),
                                   via: (map(select(.rating >= 3) | .via) | unique)})) as $U
JQ

# ---------------------------------------------------------------- worklist rows
read -r -d '' JQ_ROWS <<'JQ'
| def item($sev; $cat; $issue; $action; $details):
    {sev: $sev, cat: $cat, issue: $issue, action: $action, details: $details};
  [ ( $U[] | . as $x
      | ( (if .u.synced and .rating >= 3 then
             item(.rating; "USR-SYNCED-PRIV"; "Account synced from on-prem AD holds privileged roles";
               "Move the privileged roles to a cloud-only admin account (PIM-eligible, phishing-resistant MFA) and remove them from this account. On-prem AD controls this account: whoever can reset its password or change its groups there gets these roles.";
               "")
           else empty end),
          (if .u.enabled == false then
             item(if .rating >= 3 then 3 else 2 end; "USR-DISABLED-ROLES"; "Disabled account still holds roles";
               "Remove all role assignments, group memberships and ownerships, then delete the account (or move it out of the sync scope) after the retention period.";
               "")
           else empty end),
          (if (.u.synced | not) and .rating == 4 then
             item(2; "USR-PRIV-REVIEW"; "Cloud-only account with CRITICAL roles";
               "Confirm the roles are PIM-eligible rather than permanent, the account uses phishing-resistant MFA, and the person still needs them.";
               "")
           else empty end),
          (if (.priv | length) > 5 then
             item(2; "USR-MANY-PRIV"; "User holds many privileged roles";
               "Review with the person's manager and remove the privileged roles their current job doesn't need.";
               "")
           else empty end)
        )
      | . + {kind: "User", x: $x} ),
    ( $SG[] | select(.risk == "HIGH" or .risk == "CRITICAL") | . as $g
      | item(.risk | riskvalue; "GRP-SYNCED-PRIV"; "Group synced from on-prem AD holds privileged roles";
          "Replace it with a cloud-only, role-assignable group (ideally PIM for Groups) and move the role assignments there. Until then, restrict who can change the group in on-prem AD.";
          "")
      | . + {kind: "Group", g: {name: $g.group, id: $g.groupId, members: $g.userMembers, roles: $g.roles, synced: "yes"}} ),
    ( if $single then
        $users[0] as $t
        | $UG[] | . as $g
        | ([$M[] | select(.group.id? == $g.groupId) | .rating] | max // 0) as $gr
        | ( (if .rolesHeld != "" and .roleAssignable != "yes" and .synced != "yes" then
               item(2; "GRP-NOT-ROLEASSIGNABLE"; "Group holds roles but isn't role-assignable";
                 "Its owners, Groups Administrators and User Administrators can change its membership. Use a role-assignable group or a restricted management administrative unit, and review its owners.";
                 "")
             else empty end),
            (if .rolesHeld != "" and .age <= 90 then
               item(2; "GRP-RECENT-PRIV"; "Group created in the last 90 days holds roles";
                 "Check in the Entra audit log who created the group and who added its members, and confirm it is legitimate.";
                 "")
             else empty end),
            (if (.group | adminname) and .rolesHeld == "" then
               item(1; "GRP-ADMIN-NO-ROLE"; "Admin-sounding group with no Entra or Azure role found";
                 "Check whether it grants rights in Defender XDR, Exchange, Purview or Intune. Remove the user's membership if they don't need it.";
                 "")
             else empty end),
            (if $gr >= 3 then
               item($gr; "USR-GROUP-MEMBERSHIP"; "User gets privileged roles through this group";
                 "Confirm the user still needs this membership and remove it if not." + (if .membership == "nested" then " The membership is nested: find the group that brings the user in." else "" end);
                 "")
             else empty end)
          )
        | . + {kind: "Group", t: $t,
               g: {name: $g.group, id: $g.groupId, members: "", roles: $g.rolesHeld, synced: $g.synced,
                   membership: $g.membership, assignable: $g.roleAssignable, type: $g.type, owners: $g.owners,
                   created: $g.created}}
      else empty end )
  ]
| sort_by(-.sev, .cat, (.x.u.upn // .g.name // ""))
JQ

# ---------------------------------------------------------------- CSV
read -r -d '' JQ_CSV <<'JQ'
def risklabel: ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][.];
def yn: if . == true then "yes" elif . == false then "no" else "" end;
def csvrow: map(if . == null then "" else tostring end
                | if test("^[=+\\-@\t\r]") then "'" + . else . end   # no formulas in Excel
                | gsub("\""; "\"\"") | "\"" + . + "\"") | join($sep);
. as $rows
| (["item_id", "severity", "priority", "category", "issue", "action", "kind", "user_upn", "user_name",
  "user_synced", "user_enabled", "on_prem_account", "privileged_roles", "privileged_role_count", "held_via",
  "group_name", "group_id", "membership", "group_synced", "role_assignable", "group_type", "group_owners",
  "group_created", "roles_held", "group_user_members", "details", "detected"] | csvrow),
($rows[] | (.cat == "USR-GROUP-MEMBERSHIP") as $ug | (.x.u // (if $ug then .t else null end)) as $u
  | [ (if .x then "\(.cat):\(.x.u.id)" elif $ug then "\(.cat):\(.t.id):\(.g.id)" else "\(.cat):\(.g.id)" end),
      (.sev | risklabel), (5 - .sev), .cat, .issue, .action, .kind,
      ($u.upn // ""), ($u.name // ""), ($u.synced | yn), ($u.enabled | yn), ($u.sam // ""),
      ((.x.priv // []) | join("; ")), (if .x then (.x.priv | length) else "" end), ((.x.via // []) | join("; ")),
      (.g.name // ""), (.g.id // ""), (.g.membership // ""), (.g.synced // ""), (.g.assignable // ""),
      (.g.type // ""), (.g.owners // ""), (.g.created // ""), (.g.roles // ""), (.g.members // ""),
      .details, $detected ]
  | csvrow)
JQ

# ---------------------------------------------------------------- report.md
read -r -d '' JQ_REPORT <<'JQ'
| ($U | length) as $nu
| "# User accounts with Entra ID and Azure roles",
  "",
  "Inventory of \($detected) (user-role-inventory). Counts only.",
  "",
  ( if $scope.rootAccess == false then
      "> **Warning: incomplete inventory.** The account that ran it couldn't read the tenant root management group (no Reader role there, or a PIM role that wasn't active), so Azure role assignments cover only the subscriptions it could see. Entra ID data is complete. Re-run with the role active.",
      ""
    else empty end ),
  (if $single then "Mode: **single user** (`-u`)." else "Mode: **whole tenant**. Users read: **\($users | length)**, of which synced from on-prem: **\($users | cnt(.synced))**." end),
  "",
  "Users with at least one Entra or Azure role: **\($nu)**.",
  "",
  "## Users by risk",
  "",
  "| Risk | Users | Synced from on-prem | Cloud-only | Disabled |",
  "|---|---|---|---|---|",
  ( [4, 3, 2, 1][] as $r | ($U | map(select(.rating == $r))) as $g
    | "| \($r | risklabel) | \($g | length) | \($g | cnt(.u.synced)) | \($g | cnt(.u.synced | not)) | \($g | cnt(.u.enabled == false)) |" ),
  "",
  "## Synced and disabled accounts",
  "",
  "- Synced accounts with roles: **\($U | cnt(.u.synced))**; with HIGH or CRITICAL roles: **\($U | cnt(.u.synced and .rating >= 3))**; with CRITICAL roles: **\($U | cnt(.u.synced and .rating == 4))**",
  "- Disabled accounts that still hold roles: **\($U | cnt(.u.enabled == false))**; with HIGH or CRITICAL roles: **\($U | cnt(.u.enabled == false and .rating >= 3))**",
  "- Cloud-only accounts with CRITICAL roles: **\($U | cnt((.u.synced | not) and .rating == 4))**",
  "",
  "## How privileged access is held",
  "",
  "HIGH and CRITICAL role assignments, counted per user, role and scope.",
  "",
  "| Held | Assignments | Of which active | Of which PIM-eligible |",
  "|---|---|---|---|",
  ( [$M[] | select(.rating >= 3)] | unique_by([.user.id, .src, .role, .scope, .kind, how])
    | if length == 0 then "| (none) | | | |" else group_by(how)[]
      | "| \(.[0] | how) | \(length) | \(cnt(.kind == "active")) | \(cnt(.kind == "eligible")) |" end ),
  "",
  "## Most common privileged roles",
  "",
  "| Role @ level | Users | Synced users |",
  "|---|---|---|",
  ( [$U[] | .u as $u | .priv[] | {r: ., s: $u.synced}] | group_by(.r) | map({r: .[0].r, n: length, s: cnt(.s)})
    | sort_by(-.n, .r) | .[:15]
    | if length == 0 then "| (none) | | |" else .[] | "| \(.r) | \(.n) | \(.s) |" end ),
  "",
  "## Privilege concentration",
  "",
  "Users by number of distinct HIGH or CRITICAL roles (role @ level).",
  "",
  "| Privileged roles per user | Users | Synced |",
  "|---|---|---|",
  ( [ {l: "1", f: 1, t: 1}, {l: "2-5", f: 2, t: 5}, {l: "6-10", f: 6, t: 10}, {l: "more than 10", f: 11, t: 1e9} ][] as $b
    | ($U | map(select((.priv | length) >= $b.f and (.priv | length) <= $b.t))) as $g
    | "| \($b.l) | \($g | length) | \($g | cnt(.u.synced)) |" ),
  "",
  "## Synced groups that hold roles",
  "",
  "On-prem AD controls the membership of these groups, so whoever can change them there gets their roles.",
  "",
  "- Synced groups with roles: **\($SG | length)**; HIGH or CRITICAL: **\($SG | cnt(.risk == "HIGH" or .risk == "CRITICAL"))**",
  ( if ($SG | length) > 0 then
      "", "| Risk | Groups |", "|---|---|",
      ($SG | group_by(.risk) | sort_by(-(.[0].risk | riskvalue))[] | "| \(.[0].risk) | \(length) |")
    else empty end ),
  ( if $single then
      "",
      "## Groups of the user",
      "",
      "- Groups: **\($UG | length)** (direct: \($UG | cnt(.membership == "direct")), nested: \($UG | cnt(.membership == "nested")))",
      "- Synced from on-prem: **\($UG | cnt(.synced == "yes"))**; role-assignable: **\($UG | cnt(.roleAssignable == "yes"))**",
      "- Holding Entra or Azure roles: **\($UG | cnt(.rolesHeld != ""))**",
      "- Holding roles but **not** role-assignable (owners, Groups Administrators and User Administrators can change membership): **\($UG | cnt(.rolesHeld != "" and .roleAssignable != "yes"))**",
      "- Holding roles **and** synced from on-prem: **\($UG | cnt(.rolesHeld != "" and .synced == "yes"))**",
      "- With owners: **\($UG | cnt(.owners != ""))**",
      "- Admin-sounding name but no Entra or Azure role found (check workload RBAC: Defender XDR, Exchange, Purview, Intune): **\($UG | cnt((.group | adminname) and .rolesHeld == ""))**",
      "- Created in the last 30 days: **\($UG | cnt(.age <= 30))**, 90 days: **\($UG | cnt(.age <= 90))**, 365 days: **\($UG | cnt(.age <= 365))**",
      "",
      "| Group type | Groups |", "|---|---|",
      ($UG | group_by(.type)[] | "| \(.[0].type) | \(length) |")
    else empty end ),
  "",
  "## Worklist",
  "",
  "| Severity | Items |", "|---|---|",
  ($items[0] | map(.sev) | group_by(.) | reverse
   | if length == 0 then "| (none) | |" else .[] | "| \(.[0] | risklabel) | \(length) |" end)
JQ

SCOPE=$(cat "$DIR/raw/scope.json" 2>/dev/null || echo '{}')   # absent in runs made before it existed
ARGS=(--slurpfile m "$DIR/raw/model.jsonl" --slurpfile users "$DIR/raw/users.jsonl" --argjson scope "$SCOPE"
      --rawfile sg "$DIR/synced_groups.tsv" --rawfile ug "$UG" --arg detected "$DETECTED")
# The rows go through a file: as a command-line argument they would hit the OS limit
# (128 KB per argument on Linux, 32 KB per command line on Windows).
ITEMS=$(mktemp) || die "cannot create a temporary file"
trap 'rm -f "$ITEMS"' EXIT
jq -n -c "${ARGS[@]}" "$JQ_PRE $JQ_ROWS" > "$ITEMS" || die "building the worklist failed"
{ printf '\xEF\xBB\xBF'; jq -r --arg sep "$SEP" --arg detected "$DETECTED" "$JQ_CSV" < "$ITEMS"; } \
  > "$OUT/user-role-worklist.csv" || die "writing user-role-worklist.csv failed"
jq -n -r "${ARGS[@]}" --slurpfile items "$ITEMS" "$JQ_PRE $JQ_REPORT" > "$OUT/user-role-report.md" \
  || die "building user-role-report.md failed"

printf 'user-role-report.md     %s  (counts only - safe for the report)\n' "$OUT/user-role-report.md" >&2
printf 'user-role-worklist.csv  %s  (%s items, with names - internal)\n' "$OUT/user-role-worklist.csv" "$(jq -r 'length' < "$ITEMS")" >&2
