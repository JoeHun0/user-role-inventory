#!/usr/bin/env bash
# user-role-inventory.sh - READ-ONLY inventory of the user accounts that hold
# Entra ID directory roles or Azure RBAC roles, directly or through groups, with a
# focus on accounts and groups synced from on-prem Active Directory.
#
# Why: a synced account is controlled by on-prem AD. Whoever can reset its password
# or change its groups there also gets its cloud roles. The same goes for the members
# of a synced group. Disabled accounts that still hold roles are flagged too.
#
# Usage:
#   ./user-role-inventory.sh               whole tenant
#   ./user-role-inventory.sh -u <UPN|id>   one user, plus every group they are in
#   ./user-role-inventory.sh -E            also read PIM-eligible Azure roles
#                                             (one call per subscription and MG)
#   ./user-role-inventory.sh -o <dir>      output folder
#                                   (default ./user-role-inventory-YYYYMMDD-HHMM)
#
# Output (tab-separated, opens in LibreOffice Calc / Excel):
#   users.tsv          one row per user with at least one role, highest risk first
#   assignments.tsv    one row per user and role, and how it is held (direct or
#                      through which group)
#   synced_groups.tsv  groups synced from on-prem AD that hold roles
#   user_groups.tsv    (-u only) every group of the user, newest first: direct or
#                      nested, synced, role-assignable, owners, roles it holds
#   raw/               the JSON lines the reports are built from
#
# Only read operations are used (az rest --method GET, az graph query,
# az role ... list). Nothing in the tenant is changed.
# Not covered: PIM-eligible Entra roles (the Azure CLI's Graph token can't read
# them), Azure roles below subscription level with -E, Azure DevOps permissions.
#
# Needs: az CLI logged in (az login), the resource-graph extension, jq 1.6+.
#        Reader on the tenant root management group, and Global Reader (or
#        Directory Readers) in Entra ID.
# The output maps your tenant's privileged access: keep it private.

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Kotnyek József
# https://github.com/JoeHun0/user-role-inventory

set -uo pipefail

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; }

TARGET=""
ELIGIBLE=0
OUTDIR=""
while getopts ":u:Eo:h" opt; do
  case "$opt" in
    u) TARGET="$OPTARG" ;;
    E) ELIGIBLE=1 ;;
    o) OUTDIR="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) echo "Unknown option. Use -h for help." >&2; exit 2 ;;
  esac
done

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
warn() { printf '[%s] WARNING: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ -z "$TARGET" || "$TARGET" =~ ^[A-Za-z0-9._%+#@-]+$ ]] || die "not a user principal name or object ID: $TARGET"

command -v az >/dev/null || die "az CLI not found"
command -v jq >/dev/null || die "jq not found (sudo apt install jq)"

# Windows (Git Bash, MSYS2, WSL calling the Windows az): Windows builds of az and jq
# end their output lines with CRLF, and MSYS rewrites arguments that start with "/"
# into Windows paths (--scope /providers/... becomes C:/Program Files/Git/providers/...).
# Both make Azure answer "Bad Request". Strip the CRs and turn the rewriting off for az.
az() { MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' command az "$@" | tr -d '\r'; }
jq() { command jq "$@" | tr -d '\r'; }

az extension show --name resource-graph --only-show-errors >/dev/null 2>&1 \
  || die "resource-graph extension missing: az extension add --name resource-graph"
TENANT_ID=$(az account show --query tenantId -o tsv --only-show-errors </dev/null 2>/dev/null) \
  && [[ -n "$TENANT_ID" ]] || die "not logged in: run az login"

umask 077
OUTDIR=${OUTDIR:-"./user-role-inventory-$(date +%Y%m%d-%H%M)"}
RAW="$OUTDIR/raw"
mkdir -p "$RAW" || die "cannot create $RAW"
for f in users groups members owners direct dirdefs assignments roledefs; do
  : > "$RAW/$f.jsonl"
done

GRAPH="https://graph.microsoft.com/v1.0"
ARM="https://management.azure.com"
USEL='id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled,onPremisesSamAccountName,createdDateTime,userType'
GSEL='id,displayName,description,createdDateTime,onPremisesSyncEnabled,isAssignableToRole,securityEnabled,mailEnabled,groupTypes,membershipRule'
USER_PROJ='{id, name: .displayName, upn: .userPrincipalName, enabled: .accountEnabled,
            synced: (.onPremisesSyncEnabled == true), sam: .onPremisesSamAccountName,
            created: .createdDateTime, userType}'
GROUP_PROJ='{id, name: .displayName, description, created: .createdDateTime,
             synced: (.onPremisesSyncEnabled == true), roleAssignable: (.isAssignableToRole == true),
             security: .securityEnabled, mail: .mailEnabled, groupTypes: (.groupTypes // []),
             rule: .membershipRule}'

# GET a Microsoft Graph or ARM collection, follow the next links, print .value[] as JSON lines.
rest_all() {
  local url="$1" resp
  while [[ -n "$url" ]]; do
    resp=$(az rest --method GET --url "$url" -o json --only-show-errors </dev/null) || return 1
    jq -c '.value[]?' <<<"$resp" || return 1
    url=$(jq -r '."@odata.nextLink" // .nextLink // empty' <<<"$resp")
  done
}

# Azure Resource Graph query over the whole tenant, with paging; prints .data[] as JSON lines.
arg_all() {
  local q="$1" skip="" resp
  local args=(graph query -q "$q" --management-groups "$TENANT_ID" --first 1000 -o json --only-show-errors)
  while :; do
    if [[ -n "$skip" ]]; then
      resp=$(az "${args[@]}" --skip-token "$skip" </dev/null) || return 1
    else
      resp=$(az "${args[@]}" </dev/null) || return 1
    fi
    jq -c '.data[]?' <<<"$resp" || return 1
    skip=$(jq -r '.skip_token // empty' <<<"$resp")
    [[ -z "$skip" ]] && break
  done
}

# ---------------------------------------------------------------- 1. users and groups
if [[ -n "$TARGET" ]]; then
  log "Tenant $TENANT_ID - reading user $TARGET and their groups..."
  az rest --method GET --url "$GRAPH/users/${TARGET//#/%23}?\$select=$USEL" -o json --only-show-errors </dev/null \
    | jq -c "$USER_PROJ" > "$RAW/users.jsonl" && [[ -s "$RAW/users.jsonl" ]] \
    || die "user not found or not readable: $TARGET"
  TID=$(jq -r '.id' "$RAW/users.jsonl")
  rest_all "$GRAPH/users/$TID/transitiveMemberOf?\$select=$GSEL&\$top=999" \
    | jq -c "select(.\"@odata.type\" == \"#microsoft.graph.group\") | $GROUP_PROJ" > "$RAW/groups.jsonl" \
    || warn "group memberships not readable"
  rest_all "$GRAPH/users/$TID/memberOf?\$select=id&\$top=999" | jq -c '{id}' > "$RAW/direct.jsonl" \
    || warn "direct group memberships not readable - all groups will show as nested"
  jq -c --arg u "$TID" '{groupId: .id, memberId: $u}' "$RAW/groups.jsonl" > "$RAW/members.jsonl"
  N=$(wc -l < "$RAW/groups.jsonl")
  log "$N groups. Reading their owners..."
  i=0
  while read -r gid; do
    i=$((i + 1)); ((i % 50 == 0)) && log "  owners: $i/$N"
    rest_all "$GRAPH/groups/$gid/owners?\$select=id,displayName,userPrincipalName" \
      | jq -c --arg g "$gid" '{groupId: $g, owner: (.userPrincipalName // .displayName // .id)}' \
      >> "$RAW/owners.jsonl" || warn "group $gid: owners not readable"
  done < <(jq -r '.id' "$RAW/groups.jsonl")
else
  log "Tenant $TENANT_ID - reading all users..."
  rest_all "$GRAPH/users?\$select=$USEL&\$top=999" | jq -c "$USER_PROJ" > "$RAW/users.jsonl" \
    || die "could not list users"
  log "$(wc -l < "$RAW/users.jsonl") users. Reading all groups..."
  rest_all "$GRAPH/groups?\$select=$GSEL&\$top=999" | jq -c "$GROUP_PROJ" > "$RAW/groups.jsonl" \
    || die "could not list groups"
  log "$(wc -l < "$RAW/groups.jsonl") groups."
fi

# ---------------------------------------------------------------- 2. Entra directory roles (active)
log "Reading Entra directory roles..."
rest_all "$GRAPH/roleManagement/directory/roleDefinitions?\$select=id,displayName,templateId" \
  > "$RAW/dirdefs.jsonl" || warn "directory role definitions not readable - role names may show as IDs"
ENTRA_PROJ='{src: "entra", kind: "active", id, principalId, roleDefinitionId, scope: .directoryScopeId}'
if ! rest_all "$GRAPH/roleManagement/directory/roleAssignments?\$select=id,principalId,roleDefinitionId,directoryScopeId" \
     | jq -c "$ENTRA_PROJ" >> "$RAW/assignments.jsonl"; then
  if [[ -n "$TARGET" ]]; then
    warn "tenant-wide directory role list refused, querying the user and their groups one by one"
    while read -r p; do
      rest_all "$GRAPH/roleManagement/directory/roleAssignments?\$filter=principalId%20eq%20'$p'" \
        | jq -c "$ENTRA_PROJ" >> "$RAW/assignments.jsonl" || warn "principal $p: directory roles not readable"
    done < <(jq -r '.id' "$RAW/users.jsonl" "$RAW/groups.jsonl")
  else
    warn "directory role assignments not readable - Entra roles are missing from the reports"
  fi
fi

# ---------------------------------------------------------------- 3. Azure RBAC (active)
log "Reading Azure role assignments (Resource Graph, whole tenant)..."
AZ_PROJ='{src: "azure", kind: "active", id, principalId, roleDefinitionId, scope}'
Q_RBAC="authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend principalType = tostring(properties.principalType)
| where principalType in~ ('User', 'Group')
| project id, principalId = tostring(properties.principalId),
          roleDefinitionId = tostring(properties.roleDefinitionId), scope = tostring(properties.scope)"
arg_all "$Q_RBAC" | jq -c "$AZ_PROJ" >> "$RAW/assignments.jsonl" \
  || warn "Resource Graph role assignment query failed - Azure roles may be incomplete"

log "Reading role assignments on management groups and the root scope..."
RA_QUERY="[?principalType=='User' || principalType=='Group'].{id:id, principalId:principalId, roleDefinitionId:roleDefinitionId, scope:scope}"
ra_list() {
  az role assignment list --scope "$1" --fill-principal-name false --fill-role-definition-name false \
    --query "$RA_QUERY" -o json --only-show-errors </dev/null 2>/dev/null \
  || az role assignment list --scope "$1" --query "$RA_QUERY" -o json --only-show-errors </dev/null
}
mapfile -t MGS < <(az account management-group list --query '[].name' -o tsv --only-show-errors </dev/null) \
  || warn "could not list management groups"
for mg in "${MGS[@]}"; do
  ra_list "/providers/Microsoft.Management/managementGroups/$mg" | jq -c ".[] | $AZ_PROJ" >> "$RAW/assignments.jsonl" \
    || warn "management group $mg: role assignments not readable"
done
ra_list "/" 2>/dev/null | jq -c ".[] | select(.scope == \"/\") | $AZ_PROJ" >> "$RAW/assignments.jsonl" 2>/dev/null \
  || warn "root scope (/) role assignments not readable (needs elevated access) - skipped"

log "Reading Azure role definitions..."
Q_ROLEDEFS="authorizationresources
| where type =~ 'microsoft.authorization/roledefinitions'
| project name = tolower(name), roleName = tostring(properties.roleName)"
arg_all "$Q_ROLEDEFS" >> "$RAW/roledefs.jsonl" || warn "Resource Graph role definition query failed"
az role definition list --query '[].{name:name, roleName:roleName}' -o json --only-show-errors </dev/null \
  | jq -c '.[]' >> "$RAW/roledefs.jsonl" || warn "az role definition list failed - some role names may show as GUIDs"

# ---------------------------------------------------------------- 4. Azure RBAC (PIM-eligible, -E)
if ((ELIGIBLE)); then
  Q_SUBS="resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId"
  mapfile -t SUBS < <(arg_all "$Q_SUBS" | jq -r '.subscriptionId') || warn "could not list subscriptions"
  SCOPES=()
  for mg in "${MGS[@]}"; do SCOPES+=("/providers/Microsoft.Management/managementGroups/$mg"); done
  for s in "${SUBS[@]}"; do SCOPES+=("/subscriptions/$s"); done
  log "Reading PIM-eligible Azure roles on ${#SCOPES[@]} management groups and subscriptions..."
  EL_PROJ='select(.properties.principalType == "User" or .properties.principalType == "Group")
           | {src: "azure", kind: "eligible", id, principalId: .properties.principalId,
              roleDefinitionId: .properties.roleDefinitionId, scope: .properties.scope}'
  i=0 failed=0
  for sc in "${SCOPES[@]}"; do
    i=$((i + 1)); ((i % 25 == 0)) && log "  eligible: $i/${#SCOPES[@]}"
    rest_all "$ARM$sc/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&\$filter=atScope()" \
      2>/dev/null | jq -c "$EL_PROJ" >> "$RAW/assignments.jsonl" || failed=$((failed + 1))
  done
  ((failed)) && warn "PIM-eligible Azure roles not readable on $failed of ${#SCOPES[@]} scopes"
fi

# ---------------------------------------------------------------- 5. members of groups that hold roles
if [[ -z "$TARGET" ]]; then
  jq -r --slurpfile a "$RAW/assignments.jsonl" \
    '($a | map(.principalId | ascii_downcase) | unique) as $p | select((.id | ascii_downcase) | IN($p[])) | .id' \
    "$RAW/groups.jsonl" > "$RAW/rolegroups.txt"
  N=$(wc -l < "$RAW/rolegroups.txt")
  log "Reading members of the $N groups that hold roles..."
  i=0
  while read -r gid; do
    i=$((i + 1)); ((i % 25 == 0)) && log "  members: $i/$N"
    rest_all "$GRAPH/groups/$gid/transitiveMembers?\$select=id&\$top=999" \
      | jq -c --arg g "$gid" 'select(."@odata.type" == "#microsoft.graph.user") | {groupId: $g, memberId: .id}' \
      >> "$RAW/members.jsonl" || warn "group $gid: members not readable - its roles are missing from the user reports"
  done < "$RAW/rolegroups.txt"
fi

# ---------------------------------------------------------------- 6. build the reports
log "Building reports..."
read -r -d '' JQ_DEFS <<'JQ'
def lc: ascii_downcase;
def guid: (lc | capture("roledefinitions/(?<g>[^/]+)$").g) // lc;
def level: if .src == "entra" then
             (if .scope == "/" then "tenant"
              elif (.scope | test("^/administrativeUnits/"; "i")) then "administrativeUnit"
              else "object" end)
           elif .scope == "/" then "root"
           elif (.scope | test("^/providers/microsoft.management/managementgroups/[^/]+$"; "i")) then "managementGroup"
           elif (.scope | test("^/subscriptions/[^/]+$"; "i")) then "subscription"
           elif (.scope | test("^/subscriptions/[^/]+/resourcegroups/[^/]+$"; "i")) then "resourceGroup"
           else "resource" end;
def priv_azure: ["Owner", "User Access Administrator", "Role Based Access Control Administrator", "Contributor"];
def crit_entra: ["Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
                 "Application Administrator", "Cloud Application Administrator", "Hybrid Identity Administrator",
                 "Partner Tier2 Support", "Domain Name Administrator", "External Identity Provider Administrator",
                 "Conditional Access Administrator", "Security Administrator", "Authentication Policy Administrator",
                 "Intune Administrator", "User Administrator", "Groups Administrator", "Authentication Administrator",
                 "Exchange Administrator", "SharePoint Administrator"];
def rate: if .src == "entra" then
            (if (.role | IN(crit_entra[])) then 4
             elif .role == "Global Reader" then 2
             elif (.role | test("reader"; "i")) then 1
             else 3 end)
          elif (.role | IN(priv_azure[])) then
            (if .level == "root" or .level == "managementGroup" then 4
             elif .level == "subscription" then 3 else 2 end)
          elif (.role | test("reader"; "i")) then 1
          else 2 end;
def risklabel: ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][.];
def yn: if . == true then "yes" elif . == false then "no" else "" end;
JQ

read -r -d '' JQ_MODEL <<'JQ'
($users  | map({key: (.id | lc), value: .}) | from_entries) as $U
| ($groups | map({key: (.id | lc), value: .}) | from_entries) as $G
| ($members | group_by(.groupId | lc) | map({key: (.[0].groupId | lc), value: [.[].memberId | lc] | unique}) | from_entries) as $M
| ($roledefs | map({key: (.name | lc), value: .roleName}) | from_entries) as $rd
| ([$dirdefs[] | {key: .id, value: .displayName}] + [$dirdefs[] | select(.templateId) | {key: .templateId, value: .displayName}] | from_entries) as $dd
| $assign
| unique_by([.src, .kind, (.id | lc)])
| .[]
| . + {role: (if .src == "entra" then ($dd[.roleDefinitionId] // .roleDefinitionId)
              else ($rd[.roleDefinitionId | guid] // (.roleDefinitionId | guid)) end)}
| . + {level: level}
| . + {rating: rate}
| (.principalId | lc) as $p
| if $U[$p] then . + {user: $U[$p], via: "direct", group: null}
  elif $G[$p] then . as $a | ($M[$p] // [])[] | select($U[.]) | $a + {user: $U[.], via: ("group: " + $G[$p].name), group: $G[$p]}
  else empty end
| . + {concern: ([ (if .user.synced then "synced account" else empty end),
                   (if .user.enabled == false then "disabled account" else empty end),
                   (if .group.synced then "group synced from on-prem" else empty end) ] | join("; "))}
JQ

jq -n -c --slurpfile users "$RAW/users.jsonl" --slurpfile groups "$RAW/groups.jsonl" \
  --slurpfile members "$RAW/members.jsonl" --slurpfile roledefs "$RAW/roledefs.jsonl" \
  --slurpfile dirdefs "$RAW/dirdefs.jsonl" --slurpfile assign "$RAW/assignments.jsonl" \
  "$JQ_DEFS $JQ_MODEL" > "$RAW/model.jsonl" || die "building the model failed"

{
  printf 'risk\tuser\tname\tsynced\tenabled\tsource\trole\tassignment\tlevel\tscope\tvia\tconcern\n'
  jq -r -s "$JQ_DEFS"'
    sort_by(-.rating, (if .user.synced then 0 else 1 end), .user.upn, .role)[]
    | [(.rating | risklabel), .user.upn, .user.name, (.user.synced | yn), (.user.enabled | yn),
       (if .src == "entra" then "Entra" else "Azure" end), .role, .kind, .level, .scope, .via, .concern] | @tsv' \
    "$RAW/model.jsonl"
} > "$OUTDIR/assignments.tsv"

{
  printf 'risk\tuser\tname\tsynced\tenabled\tonPremAccount\tentraRoles\tazureRoles\tprivilegedRoles\tconcern\n'
  jq -r -s "$JQ_DEFS"'
    group_by(.user.id | lc)
    | map({u: .[0].user, rating: (map(.rating) | max),
           entra: (map(select(.src == "entra")) | length), azure: (map(select(.src == "azure")) | length),
           priv: (map(select(.rating >= 3) | "\(.role) @ \(.level)\(if .kind == "eligible" then " (eligible)" else "" end)") | unique | join("; ")),
           concern: (map(.concern | split("; ")[]) | unique | map(select(. != "")) | join("; "))})
    | sort_by(-.rating, (if .u.synced then 0 else 1 end), .u.upn)[]
    | [(.rating | risklabel), .u.upn, .u.name, (.u.synced | yn), (.u.enabled | yn), (.u.sam // ""),
       .entra, .azure, .priv, .concern] | @tsv' \
    "$RAW/model.jsonl"
} > "$OUTDIR/users.tsv"

# groups synced from on-prem that hold roles (from the assignments, not only via known members)
read -r -d '' JQ_GROUPROLES <<'JQ'
($roledefs | map({key: (.name | lc), value: .roleName}) | from_entries) as $rd
| ([$dirdefs[] | {key: .id, value: .displayName}] + [$dirdefs[] | select(.templateId) | {key: .templateId, value: .displayName}] | from_entries) as $dd
| ($assign | unique_by([.src, .kind, (.id | lc)])
   | map(. + {role: (if .src == "entra" then ($dd[.roleDefinitionId] // .roleDefinitionId)
                     else ($rd[.roleDefinitionId | guid] // (.roleDefinitionId | guid)) end)})
   | map(. + {level: level}) | map(. + {rating: rate})
   | group_by(.principalId | lc) | map({key: (.[0].principalId | lc), value: .}) | from_entries) as $byP
| ($members | group_by(.groupId | lc) | map({key: (.[0].groupId | lc), value: length}) | from_entries) as $cnt
JQ

{
  printf 'risk\tgroup\tgroupId\tuserMembers\troles\n'
  jq -n -r --slurpfile groups "$RAW/groups.jsonl" --slurpfile members "$RAW/members.jsonl" \
    --slurpfile roledefs "$RAW/roledefs.jsonl" --slurpfile dirdefs "$RAW/dirdefs.jsonl" \
    --slurpfile assign "$RAW/assignments.jsonl" "$JQ_DEFS $JQ_GROUPROLES"'
    | [$groups[] | select(.synced) | . as $g | ($byP[.id | lc] // empty)
       | {g: $g, rating: (map(.rating) | max), n: ($cnt[$g.id | lc] // 0),
          roles: (map("\(.role) @ \(.scope)\(if .kind == "eligible" then " (eligible)" else "" end)") | unique | join("; "))}]
    | sort_by(-.rating, .g.name)[]
    | [(.rating | risklabel), .g.name, .g.id, (if $ARGS.named.target then "" else .n end), .roles] | @tsv' \
    --argjson target "$([[ -n "$TARGET" ]] && echo true || echo false)"
} > "$OUTDIR/synced_groups.tsv"

if [[ -n "$TARGET" ]]; then
  {
    printf 'created\tgroup\tgroupId\tmembership\tsynced\troleAssignable\ttype\towners\trolesHeld\tdescription\n'
    jq -n -r --slurpfile groups "$RAW/groups.jsonl" --slurpfile members "$RAW/members.jsonl" \
      --slurpfile roledefs "$RAW/roledefs.jsonl" --slurpfile dirdefs "$RAW/dirdefs.jsonl" \
      --slurpfile assign "$RAW/assignments.jsonl" --slurpfile direct "$RAW/direct.jsonl" \
      --slurpfile owners "$RAW/owners.jsonl" "$JQ_DEFS $JQ_GROUPROLES"'
      | ($direct | map(.id | lc)) as $d
      | ($owners | group_by(.groupId | lc) | map({key: (.[0].groupId | lc), value: map(.owner) | unique | join(", ")}) | from_entries) as $own
      | $groups | sort_by(.created // "") | reverse | .[]
      | [ .created // "", .name, .id,
          (if (.id | lc | IN($d[])) then "direct" else "nested" end),
          (.synced | yn), (.roleAssignable | yn),
          ((if any(.groupTypes[]; . == "Unified") then "Microsoft 365"
            elif .security and .mail then "mail-enabled security"
            elif .security then "security" else "distribution" end)
           + (if any(.groupTypes[]; . == "DynamicMembership") then " (dynamic)" else "" end)),
          ($own[.id | lc] // ""),
          (($byP[.id | lc] // []) | map("\(.role) @ \(.scope)\(if .kind == "eligible" then " (eligible)" else "" end)") | unique | join("; ")),
          ((.description // "") | gsub("[\t\r\n]+"; " ")) ] | @tsv'
  } > "$OUTDIR/user_groups.tsv"
fi

# ---------------------------------------------------------------- 7. summary
log "Done."
jq -r -s 'group_by(.user.id) | map(.[0].user) as $u
  | "  users with roles:                    \($u | length)",
    "  synced users with roles:             \($u | map(select(.synced)) | length)",
    "  disabled users with roles:           \($u | map(select(.enabled == false)) | length)"' "$RAW/model.jsonl" >&2
jq -r -s 'map(select(.user.synced and .rating >= 3)) | group_by(.user.id) | length
  | "  synced users with HIGH/CRITICAL roles: \(.)"' "$RAW/model.jsonl" >&2
log "  synced groups holding roles: $(($(wc -l < "$OUTDIR/synced_groups.tsv") - 1))"
[[ -n "$TARGET" ]] && log "  groups of $TARGET: $(wc -l < "$RAW/groups.jsonl") (see user_groups.tsv, newest first)"
log "Reports in $OUTDIR (keep them private)."
