#!/usr/bin/env bash
# user-role-summary.sh - turns a user-role-inventory output folder into a short summary
# in Markdown: users per risk level, synced and disabled accounts with roles, how
# privileged access is held (direct, cloud group, synced group), the most common
# privileged roles, privilege concentration, and synced groups that hold roles.
# For a -u folder it also summarises the user's groups: type, age, owners, roles held.
#
# Usage:
#   ./user-role-summary.sh <output folder>      counts only - safe to paste into a report
#   ./user-role-summary.sh -n <output folder>   also list users, groups and roles by name
#                                               (internal use)
#
# Reads raw/model.jsonl, raw/users.jsonl, synced_groups.tsv and (if present)
# user_groups.tsv from the folder. Needs only jq; no Azure access.

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Kotnyek József
# https://github.com/JoeHun0/user-role-inventory

set -uo pipefail

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; }

NAMES=0
while getopts ":nh" opt; do
  case "$opt" in
    n) NAMES=1 ;;
    h) usage; exit 0 ;;
    *) echo "Unknown option. Use -h for help." >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
(($# == 1)) || die "give one user-role-inventory output folder (-h for help)"
DIR="$1"
[[ -f "$DIR/raw/model.jsonl" && -s "$DIR/raw/users.jsonl" && -s "$DIR/synced_groups.tsv" ]] \
  || die "raw/model.jsonl, raw/users.jsonl or synced_groups.tsv not found in $DIR - is this a user-role-inventory output folder?"
command -v jq >/dev/null || die "jq not found (sudo apt install jq)"
jq() { command jq "$@" | tr -d '\r'; }   # Windows jq ends lines with CRLF

UG="$DIR/user_groups.tsv"
[[ -s "$UG" ]] || UG=/dev/null

jq -n -r --slurpfile m "$DIR/raw/model.jsonl" --slurpfile users "$DIR/raw/users.jsonl" \
  --rawfile sg "$DIR/synced_groups.tsv" --rawfile ug "$UG" \
  --argjson names "$NAMES" --arg dir "$DIR" '
def risklabel: ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][.];
def cnt(f): map(select(f)) | length;
def tsv: split("\n") | map(select(length > 0) | split("\t"))
         | if length == 0 then [] else .[0] as $h | [.[1:][] | [$h, .] | transpose | map({key: .[0], value: .[1]}) | from_entries] end;
def ts: if . == null or . == "" then null
        else (sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | try fromdateiso8601 catch null) end;
def rlabel: "\(.role) @ \(.level) [\(if .src == "entra" then "Entra" else "Azure" end)]";
def how: if .via == "direct" then "direct"
         elif .group.synced then "through a synced group"
         else "through a cloud group" end;
def adminname: test("admin|adm\\b|owner|privileged|security|global|contributor|operator"; "i");

($sg | tsv) as $SG
| ($ug | tsv) as $UG
| ($UG | length > 0) as $single
| $m as $M
| ($M | group_by(.user.id) | map({u: .[0].user, rating: (map(.rating) | max), rows: .,
                                   priv: (map(select(.rating >= 3) | rlabel) | unique)})) as $U
| ($U | length) as $nu
| (
  "# user-role-inventory summary",
  "",
  "Source: `\($dir)`. Generated \(now | strftime("%Y-%m-%d %H:%M")) UTC.",
  "",
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
  ( [$M[] | select(.rating >= 3)] | unique_by([.user.id, .src, .role, .scope, .kind, how]) | group_by(how)[]
    | "| \(.[0] | how) | \(length) | \(cnt(.kind == "active")) | \(cnt(.kind == "eligible")) |" ),
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
      ($SG | group_by(.risk) | sort_by(.[0].risk | ["CRITICAL", "HIGH", "MEDIUM", "LOW"] | index(.))[] | "| \(.[0].risk) | \(length) |")
    else empty end ),
  ( if $single then
      ($UG | map(. + {age: ((now - (.created | ts // now)) / 86400)})) as $G
      | "",
        "## Groups of the user",
        "",
        "- Groups: **\($G | length)** (direct: \($G | cnt(.membership == "direct")), nested: \($G | cnt(.membership == "nested")))",
        "- Synced from on-prem: **\($G | cnt(.synced == "yes"))**; role-assignable: **\($G | cnt(.roleAssignable == "yes"))**",
        "- Holding Entra or Azure roles: **\($G | cnt(.rolesHeld != ""))**",
        "- Holding roles but **not** role-assignable (owners, Groups Administrators and User Administrators can change membership): **\($G | cnt(.rolesHeld != "" and .roleAssignable != "yes"))**",
        "- Holding roles **and** synced from on-prem: **\($G | cnt(.rolesHeld != "" and .synced == "yes"))**",
        "- With owners: **\($G | cnt(.owners != ""))**",
        "- Admin-sounding name but no Entra or Azure role found (check workload RBAC: Defender XDR, Exchange, Purview, Intune): **\($G | cnt((.group | adminname) and .rolesHeld == ""))**",
        "- Created in the last 30 days: **\($G | cnt(.age <= 30))**, 90 days: **\($G | cnt(.age <= 90))**, 365 days: **\($G | cnt(.age <= 365))**",
        "",
        "| Group type | Groups |", "|---|---|",
        ($G | group_by(.type)[] | "| \(.[0].type) | \(length) |")
    else empty end ),
  ( if $names == 1 then
      "",
      "## Users with CRITICAL roles, and synced or disabled users with HIGH roles (internal - contains names)",
      "",
      "| Risk | User | Synced | Enabled | Privileged roles |",
      "|---|---|---|---|---|",
      ( $U | map(select(.rating == 4 or (.rating == 3 and (.u.synced or .u.enabled == false))))
        | sort_by(-.rating, (if .u.synced then 0 else 1 end), .u.upn)[]
        | "| \(.rating | risklabel) | \(.u.upn) | \(if .u.synced then "yes" else "no" end) | \(if .u.enabled == false then "no" else "yes" end) | \(.priv | join("; ")) |" ),
      "",
      "## Synced groups that hold roles (internal - contains names)",
      "",
      "| Risk | Group | User members | Roles |", "|---|---|---|---|",
      ( $SG[] | "| \(.risk) | \(.group) | \(.userMembers) | \(.roles) |" ),
      ( if $single then
          "",
          "## Groups of the user that hold roles or have admin-sounding names (internal - contains names)",
          "",
          "| Created | Group | Membership | Synced | Role-assignable | Owners | Roles held |",
          "|---|---|---|---|---|---|---|",
          ( $UG[] | select(.rolesHeld != "" or (.group | adminname))
            | "| \(.created) | \(.group) | \(.membership) | \(.synced) | \(.roleAssignable) | \(.owners) | \(.rolesHeld) |" )
        else empty end )
    else empty end )
)'
