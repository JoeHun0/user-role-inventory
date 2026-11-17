# user-role-inventory

A read-only Bash script that lists every **user account holding Entra ID directory roles or Azure RBAC
roles**, directly or through groups. It flags accounts and groups **synced from on-prem Active
Directory**, and accounts that are **disabled but still hold roles**.

A synced account is controlled from on-prem AD. Whoever can reset its password or change its groups
there also gets its cloud roles, and so does anyone who controls a synced group that holds roles.

```bash
git clone https://github.com/JoeHun0/user-role-inventory.git
cd user-role-inventory
./user-role-inventory.sh                          # whole tenant
./user-role-inventory.sh -u someone@example.com   # one user and every group they are in
./user-role-inventory.sh -E                       # also PIM-eligible Azure roles
./user-role-inventory.sh -o ~/reports/admins      # output folder
```

## Output

Tab-separated files in `./user-role-inventory-YYYYMMDD-HHMM/`. Files are created mode `600`.

| File | Contents |
|---|---|
| `users.tsv` | One row per user with a role: risk, UPN, synced, enabled, on-prem account name, number of Entra and Azure roles, the HIGH/CRITICAL roles, concerns |
| `assignments.tsv` | One row per user and role: Entra or Azure, role, active or eligible, level, scope, and how it is held (`direct` or `group: <name>`) |
| `synced_groups.tsv` | Groups synced from on-prem AD that hold roles, with their roles and number of user members |
| `user_groups.tsv` | (`-u` only) Every group of the user, **newest first**: direct or nested membership, synced, role-assignable, type, owners, roles the group holds, description |
| `raw/` | The JSON lines the reports are built from |

`-u` is meant for looking at one account closely. Groups created recently, groups with owners you
don't recognise, and role-holding groups the person shouldn't be in stand out at the top.

## Risk rating

A heuristic to sort by, not a verdict.

| Rating | Entra role | Azure role |
|---|---|---|
| **CRITICAL** | Tier-0 or takeover-capable: Global, Privileged Role, Privileged Authentication, Application, Cloud Application, Hybrid Identity, Security, Conditional Access, User, Groups, Authentication, Intune, Exchange, SharePoint Administrator, and similar | Owner, Contributor, User Access Administrator or RBAC Administrator at root or management-group scope |
| **HIGH** | Any other Entra role that isn't a reader role | The same roles at subscription scope |
| **MEDIUM** | Global Reader | Those roles below subscription scope, or any other non-reader role |
| **LOW** | Other reader roles | Reader roles |

## Summary for reports

`user-role-summary.sh` turns an output folder into a short Markdown summary. It needs only `jq`, no
Azure access:

```bash
./user-role-summary.sh user-role-inventory-20261117-0930      # counts only
./user-role-summary.sh -n user-role-inventory-20261117-0930   # plus users and groups by name
```

It shows:
- users per risk level, split into synced, cloud-only and disabled
- synced and disabled accounts with HIGH or CRITICAL roles
- how privileged access is held: direct, through a cloud group, or through a synced group (active vs PIM-eligible)
- the most common privileged roles
- privilege concentration (how many privileged roles single users collect)
- synced groups that hold roles

For a `-u` folder it also summarises the user's groups:
- direct vs nested membership; synced; role-assignable
- groups holding roles that their owners or Groups Administrators can change
- admin-sounding groups with no Entra or Azure role found (check workload RBAC)
- groups created in the last 30, 90 and 365 days

**Without `-n`, the summary contains no user, group or role-scope names**, so it can go into a report
or ticket. Treat the `-n` version like the inventory itself.

## Requirements

- Bash 4+, jq 1.6+, Azure CLI with `az login` and `az extension add --name resource-graph`.
  Works on Linux, WSL, macOS with Homebrew `bash`, and Git Bash on Windows.
- Azure: **Reader** on the tenant root management group. Entra ID: **Global Reader** (or Directory
  Readers).

## Safety

- **Read-only:** `az rest --method GET`, `az graph query`, `az role ... list`.
- **The output maps your privileged access.** Keep it private and never commit it.

## Limitations

- **PIM-eligible Entra roles** aren't read: the Azure CLI's Graph token can't read them. Check them in
  **Entra ID → Roles and administrators → (role) → Eligible assignments**.
- **PIM-eligible Azure roles** (`-E`) are read at management-group and subscription scope only, not at
  resource-group or resource level.
- **Root scope `/`** needs elevated access. Without it, it's skipped with a warning.
- Only Entra and Azure roles. Azure DevOps permissions, Microsoft 365 workload roles (Exchange RBAC,
  SharePoint site admins) and on-prem AD groups that aren't synced aren't covered.
- Whole-tenant mode lists all users and groups and reads the members of every group that holds a role.
  In large tenants this takes a few minutes.

## Tests

```bash
tests/run-tests.sh
```

These run against a mock `az` with a small fictional tenant, plus a simulated Git Bash run. Only `bash`
and `jq` are needed. They also run on every push through GitHub Actions.

## License

[MIT](LICENSE)
