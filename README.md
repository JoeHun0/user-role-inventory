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

## Quick start

1. Sign in with the Azure CLI and add the Resource Graph extension (once):
   ```bash
   az login
   az extension add --name resource-graph
   ```
2. Run the inventory. It only reads. Expect a few minutes; longer with `-E` (one call per subscription) or many role-holding groups:
   ```bash
   ./user-role-inventory.sh      # or: -u someone@example.com for one user
   ```
   The results go to a new folder, `./user-role-inventory-YYYYMMDD-HHMM/`.
3. Turn the results into a report and a worklist:
   ```bash
   ./user-role-summary.sh user-role-inventory-YYYYMMDD-HHMM
   ```
4. Use the two files it writes into the folder:
   - **`user-role-report.md`**: counts only, with no names. Paste it into your report or ticket.
   - **`user-role-worklist.csv`**: one row per thing to fix, with severity, what to do and the details. Load it into
     Excel (*Data → From Text/CSV*) and assign rows to the people who fix them.

   Everything else in the folder (the `.tsv` files and `raw/`) is the detailed inventory. Keep it private.

On Windows, run the scripts in **Git Bash** or **WSL** with the Azure CLI installed. Run them from a folder
outside any git repository, so the results can't be committed by accident.

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

For a shareable summary and a to-do list, run `user-role-summary.sh` on the folder: see [Report and worklist](#report-and-worklist).

## Risk rating

A heuristic to sort by, not a verdict.

| Rating | Entra role | Azure role |
|---|---|---|
| **CRITICAL** | Tier-0 or takeover-capable: Global, Privileged Role, Privileged Authentication, Application, Cloud Application, Hybrid Identity, Security, Conditional Access, User, Groups, Authentication, Intune, Exchange, SharePoint Administrator, and similar | Owner, Contributor, User Access Administrator or RBAC Administrator at root or management-group scope |
| **HIGH** | Any other Entra role that isn't a reader role | The same roles at subscription scope |
| **MEDIUM** | Global Reader | Those roles below subscription scope, or any other non-reader role |
| **LOW** | Other reader roles | Reader roles |

## Report and worklist

`user-role-summary.sh` turns an output folder into two files. It needs only `jq`, no Azure access:

```bash
./user-role-summary.sh user-role-inventory-20261117-0930             # writes both files into that folder
./user-role-summary.sh -s ';' user-role-inventory-20261117-0930      # ";" as CSV separator
./user-role-summary.sh -o ~/reports user-role-inventory-20261117-0930   # writes them somewhere else
```

| File | Contents | Share? |
|---|---|---|
| `user-role-report.md` | Counts only: users per risk level, synced and disabled accounts with roles, how privileged access is held, the most common privileged roles, privilege concentration, synced groups with roles; for a `-u` folder also the user's groups by type, age, owners and roles held | Yes. No names, IDs or IP addresses, so it can go into a report or ticket |
| `user-role-worklist.csv` | One row per thing to fix, with severity, priority (1 = most urgent), category, issue, the action to take, and the details needed to do it: user UPN and name, synced, enabled, on-prem account, privileged roles and how they are held; group name and ID, membership, synced, role-assignable, type, owners, created, roles held | Internal only. Share single rows with the people who fix them |

Worklist categories: `USR-SYNCED-PRIV` (synced account with privileged roles), `USR-DISABLED-ROLES`, `USR-PRIV-REVIEW`, `USR-MANY-PRIV`, `GRP-SYNCED-PRIV`; from a `-u` folder also `USR-GROUP-MEMBERSHIP`, `GRP-NOT-ROLEASSIGNABLE`, `GRP-RECENT-PRIV`, `GRP-ADMIN-NO-ROLE`.

Notes on the CSV:
- **`item_id` (category:object ID; category:userId:groupId for memberships) stays the same between runs.** Use it as the key in a tracking spreadsheet: load the CSV with *Data → From Text/CSV* (Power Query), keep columns like assignee, status and due date in a separate table joined on `item_id`, and refresh after the next run. Fixed items drop out of the CSV.
- **Encoding:** UTF-8 with a byte-order mark, so Excel shows accented characters correctly. Values that start with `=`, `+`, `-` or `@` get a leading `'`, so names can't run as Excel formulas.
- **Separator:** `,` by default. Excel with a Hungarian or German locale expects `;` when you open the file by double-clicking, so use `-s ';'` for that.

## Requirements

- Bash 4+, jq 1.6+, Azure CLI with `az login` and `az extension add --name resource-graph`.
  Works on Linux, WSL, macOS with Homebrew `bash`, and Git Bash on Windows.
- Azure: **Reader** on the tenant root management group. Entra ID: **Global Reader** (or Directory
  Readers).
  If the account can't read the tenant root management group, for example because a **PIM role isn't active**,
  the script warns at the start and the summary report says the inventory is incomplete. Activate the role
  and run `az login` again before you start.

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
