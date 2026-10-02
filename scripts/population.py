"""PurpleForge population generator — full replacement for vendor/BadBlood.

Deterministically precomputes an entire domain's AD population (OU tree,
users, groups, computers, group memberships, and BadBlood-style "noise" ACL
grants) in Python, before any deployment happens — unlike BadBlood itself,
which draws its randomness on the live Windows host at Ansible-runtime via
PowerShell's `Get-Random`/a CSPRNG, and whose per-user passwords are
genuinely never recoverable afterward.

This is a deliberate, explicit departure from CLAUDE.md's "wrap mature
upstream projects rather than reinventing" principle, scoped specifically to
BadBlood (see .claude/plans / the session that introduced this module for
the reasoning) — GOAD, Vulnerable-AD, and ansible-lockdown remain wrapped
exactly as before.

Every ratio/naming-pattern/OU-topology rule below was read directly out of
vendor/BadBlood's own PowerShell source (AD_Users_Create/CreateUsers.ps1,
AD_Groups_Create/CreateGroup.ps1 + AddRandomToGroups.ps1,
AD_Computers_Create/CreateComputers.ps1, AD_OU_CreateStructure/
CreateOUStructure.ps1, AD_Permissions_Randomizer/
GenerateRandomPermissions.ps1) rather than invented — the goal is to match
BadBlood's actual realism, not exceed it. One deliberate exception: every
user's password is generated and recorded here (never irrecoverable), since
the whole point of this replacement is that PurpleForge now documents the
full domain ahead of time.

Scoped-down from BadBlood for v1 (see the plan's "Explicitly cut" section):
no per-user job-title/department/manager attributes (BadBlood doesn't set
these either); the "critical system group" and "DomainLocal group"
membership-padding passes are merged into one fixed representative list of
built-in groups (BadBlood queries live AD for every isCriticalSystemObject
group, which this offline generator can't do) rather than modeling AD's
exact group-scope taxonomy.
"""

from __future__ import annotations

import random

# Fixed OU topology (BadBlood's AD_OU_CreateStructure/CreateOUStructure.ps1
# is not randomized either — only which houses' codes populate the
# department-coded branches is theme-driven).
_ADMIN_TIERS = ("Tier 0", "Tier 1", "Tier 2", "Staging")
_ADMIN_OBJECT_TIERS = ("Tier 0", "Tier 1", "Tier 2")
_ADMIN_OBJECT_SUFFIXES = ("Accounts", "Servers", "Devices", "Permissions", "Roles")
_DEPT_TOP_LEVEL_OUS = ("Tier 1", "Tier 2", "Stage")
_DEPT_SUB_OUS = ("ServiceAccounts", "Groups", "Devices", "Test")
_FLAT_TOP_LEVEL_OUS = ("Quarantine", "Grouper-Groups", "Testing", ".SecFrame.com")

_TIER_PREFIX = {"Tier 0": "T0", "Tier 1": "T1", "Tier 2": "T2"}

# BadBlood's own GenerateRandomPermissions.ps1 / AddRandomToGroups.ps1 pad
# membership into every "critical system" group found live in AD. This
# generator runs offline (no live AD to query), so it uses a fixed,
# representative subset of the built-in groups every fresh AD domain always
# has — enough to reproduce the realism (a few random users landing in
# privileged built-ins) without needing to enumerate AD's full well-known-SID
# list.
BUILT_IN_PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "DnsAdmins",
    "Group Policy Creator Owners",
    "Remote Desktop Users",
    "Event Log Readers",
    "Cryptographic Operators",
]

# AD group-nesting scope rule (verified on a real deploy — "Could not add
# member(s) to one or more ADGroup" for every attempt to nest a
# Domain-Local-scope built-in as a MEMBER of a Global-scope group): a Global
# group can only contain accounts and OTHER GLOBAL groups from the same
# domain — not a Domain Local group, and (also verified live — "Enterprise
# Admins" alone failed the same way even after excluding the Domain Local
# ones) not a Universal group either. Most of BUILT_IN_PRIVILEGED_GROUPS
# above (Administrators, Account Operators, Backup Operators, Server
# Operators, Print Operators, DnsAdmins, Remote Desktop Users, Event Log
# Readers, Cryptographic Operators) are Domain Local scope, and Enterprise
# Admins is Universal scope — all fine as a membership-padding *target* (any
# scope can receive user/group members appropriately), but none of them are
# nestable *into* the Global-scope bulk groups _generate_groups creates.
# Domain Admins and Group Policy Creator Owners are the only two built-ins
# here that are genuinely Global scope.
GLOBAL_SCOPE_BUILT_IN_GROUPS = ["Domain Admins", "Group Policy Creator Owners"]

# BadBlood's AD_Computers_Create/CreateComputers.ps1: workstation type roll
# (uniform 1/3 each) and server-application roll (APPS has 2/6 weight since
# both roll-value 0 and the else-fallback land on it, the rest 1/6 each).
_WORKSTATION_TYPES = ("WKS", "LPT", "VIR")
_SERVER_TYPES = ("APPS", "WEBS", "DBAS", "SECS", "CTRX", "APPS")

# BadBlood's own AD_Groups_Create/CreateGroup.ps1 draws the "application"
# word for group names from a leaked-password wordlist (hotmail.txt) purely
# as flavor text, not as real credentials. A small fixed list here achieves
# the same "plausible-looking bulk group name" effect deterministically.
_GROUP_NAME_WORDS = [
    "reports",
    "backup",
    "sync",
    "portal",
    "gateway",
    "monitor",
    "cluster",
    "archive",
    "staging",
    "pipeline",
    "queue",
    "cache",
    "registry",
    "vault",
    "billing",
    "ledger",
    "intake",
    "export",
    "import",
    "audit",
]


def _domain_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))


def _ou_path(ancestor_names: list[str], domain_dn: str) -> str:
    """AD path of the *parent* container for an OU whose ancestors (root to
    leaf, NOT including the OU itself) are ancestor_names — this is exactly
    what community.windows.win_domain_ou's `path:` parameter expects."""
    if not ancestor_names:
        return domain_dn
    return ",".join(f"OU={n}" for n in reversed(ancestor_names)) + "," + domain_dn


def _build_ou_tree(houses: list[dict], domain_dn: str) -> list[dict]:
    """Returns every OU in creation order (parents always before their
    children — required for community.windows.win_domain_ou to apply them
    in a single unbroken pass)."""
    ous: list[dict] = []

    def add(ancestor_names: list[str], name: str) -> list[str]:
        ous.append({"name": name, "path": _ou_path(ancestor_names, domain_dn)})
        return ancestor_names + [name]

    admin = add([], "Admin")
    for tier in _ADMIN_TIERS:
        tier_path = add(admin, tier)
        if tier in _ADMIN_OBJECT_TIERS:
            prefix = _TIER_PREFIX[tier]
            for suffix in _ADMIN_OBJECT_SUFFIXES:
                add(tier_path, f"{prefix}-{suffix}")

    for top in _DEPT_TOP_LEVEL_OUS:
        top_path = add([], top)
        for h in houses:
            house_path = add(top_path, h["code"])
            for sub in _DEPT_SUB_OUS:
                add(house_path, sub)

    people = add([], "People")
    for h in houses:
        add(people, h["code"])
    add(people, "Deprovisioned")
    add(people, "Unassociated")

    for name in _FLAT_TOP_LEVEL_OUS:
        add([], name)

    return ous


def _dedupe_name(rng: random.Random, base: str, used: set[str], max_len: int = 20) -> str:
    name = base[:max_len]
    if name not in used:
        used.add(name)
        return name
    n = 2
    while True:
        suffix = str(n)
        candidate = base[: max_len - len(suffix)] + suffix
        if candidate not in used:
            used.add(candidate)
            return candidate
        n += 1


def _generate_users(rng: random.Random, count: int, vocab: dict, ou_paths: list[str], generate_password) -> list[dict]:
    users = []
    used_names: set[str] = set()
    for _ in range(count):
        is_service = rng.randint(1, 100) <= 3  # BadBlood: ~3% service accounts
        if is_service:
            base = f"{rng.randint(100, 9999999999)}SA"
            display = base
        else:
            surname = rng.choice(vocab["family_names"])
            given = rng.choice(vocab["given_names_male"] if rng.choice((0, 1)) else vocab["given_names_female"])
            base = f"{given}_{surname}"
            display = base
        sam = _dedupe_name(rng, base, used_names)

        password_in_desc = rng.randint(1, 1000) < 10  # BadBlood: ~1%
        password = generate_password(rng=rng)
        description = (
            f"Just so I dont forget my password is {password}"
            if password_in_desc
            else "Created by PurpleForge population generator."
        )

        users.append(
            {
                "name": sam,
                "display_name": display,
                "sam_account_name": sam,
                "password": password,
                "description": description,
                "ou": rng.choice(ou_paths),  # BadBlood: flat-uniform across every OU, not weighted
                "is_service_account": is_service,
                "password_in_description": password_in_desc,
                "asrep_roastable": rng.randint(1, 1000)
                < 50,  # BadBlood: ~5% (consolidated from its two redundant rolls)
            }
        )
    return users


def _generate_groups(
    rng: random.Random, count: int, ou_paths: list[str], user_names: list[str], extra_groups: list[dict]
) -> list[dict]:
    groups = []
    used_names: set[str] = set()
    for _ in range(count):
        owner = rng.choice(user_names) if user_names else None
        prefix = (owner or "xx")[:2]
        word = rng.choice(_GROUP_NAME_WORDS)
        function = "admingroup" if rng.randint(1, 100) <= 25 else "distlist"  # BadBlood: 25/75 split
        base = f"{prefix}-{word}-{function}"
        name = _dedupe_name(rng, base, used_names, max_len=64)
        groups.append(
            {
                "name": name,
                "ou": rng.choice(ou_paths),
                "managed_by": owner,
                "curated": False,
                "description": f"Bulk population group (owner: {owner})" if owner else "Bulk population group.",
            }
        )
    for g in extra_groups:
        name = _dedupe_name(rng, g["name"], used_names, max_len=64)
        groups.append(
            {
                "name": name,
                "ou": None,  # curated groups sit at the domain root, matching today's ad_theming_overlay behavior
                "managed_by": None,
                "curated": True,
                "description": g["description"],
            }
        )
    return groups


def _generate_computers(rng: random.Random, count: int, houses: list[dict], user_names: list[str]) -> list[dict]:
    computers = []
    counters: dict[str, int] = {}
    for _ in range(count):
        dept_code = rng.choice(houses)["code"] if houses else "GEN"
        is_workstation = rng.choice((0, 1)) == 0
        if is_workstation:
            wtype = rng.choice(_WORKSTATION_TYPES)
            prefix = f"{dept_code}W{wtype}"
            # BadBlood: nominal path is OU=Desktops/Laptops,OU=Technology,<domain>,
            # but CreateOUStructure.ps1 never creates OU=Technology — so this
            # always falls back to OU=Admin. Replicating that exact fallback
            # for parity rather than "fixing" behavior BadBlood itself never has.
            ou = "Admin"
        else:
            stype = rng.choice(_SERVER_TYPES)
            prefix = f"{dept_code}{stype}"
            ou = None  # servers: flat-uniform random OU, same as users/groups
        n = counters.get(prefix, 1000000)
        counters[prefix] = n + 1
        name = f"{prefix}{n}"
        computers.append(
            {
                "name": name,
                "ou": ou,  # None means "caller picks a random OU from the tree"
                "managed_by": rng.choice(user_names) if user_names else None,
                "extra_spn": rng.randint(1, 100) <= 10,  # BadBlood: ~10%
                "is_workstation": is_workstation,
            }
        )
    return computers


def _generate_memberships(
    rng: random.Random, users: list[dict], groups: list[dict], computers: list[dict]
) -> list[dict]:
    memberships: list[dict] = []
    user_names = [u["name"] for u in users]
    group_names = [g["name"] for g in groups]
    computer_names = [c["name"] for c in computers]

    def add(group: str, member: str, member_type: str) -> None:
        memberships.append({"group": group, "member": member, "member_type": member_type})

    # BadBlood AddRandomToGroups.ps1: 80% of users into 1-10 random groups.
    participating_users = rng.sample(user_names, k=round(len(user_names) * 0.8)) if user_names else []
    for u in participating_users:
        if not group_names:
            break
        for g in rng.sample(group_names, k=min(rng.randint(1, 10), len(group_names))):
            add(g, u, "user")

    # 2-5 random users padded into every built-in privileged group.
    for g in BUILT_IN_PRIVILEGED_GROUPS:
        if not user_names:
            break
        for u in rng.sample(user_names, k=min(rng.randint(2, 5), len(user_names))):
            add(g, u, "user")

    # 20% of (non-curated) groups nested inside 1-2 other groups.
    bulk_group_names = [g["name"] for g in groups if not g["curated"]]
    nestable = rng.sample(bulk_group_names, k=round(len(bulk_group_names) * 0.2)) if bulk_group_names else []
    for g in nestable:
        targets = [n for n in bulk_group_names if n != g]
        if not targets:
            continue
        for parent in rng.sample(targets, k=min(rng.randint(1, 2), len(targets))):
            add(parent, g, "group")

    # Global/Universal-scope built-in groups nested into 1-3 random bulk
    # groups — BadBlood's characteristic hidden-privilege-escalation-via-
    # nesting noise. Domain-Local-scope built-ins (most of
    # BUILT_IN_PRIVILEGED_GROUPS) are excluded here — AD forbids nesting a
    # Domain Local group as a member of a Global-scope group (see
    # GLOBAL_SCOPE_BUILT_IN_GROUPS's comment).
    for g in GLOBAL_SCOPE_BUILT_IN_GROUPS:
        if not bulk_group_names:
            break
        for parent in rng.sample(bulk_group_names, k=min(rng.randint(1, 3), len(bulk_group_names))):
            add(parent, g, "group")

    # 10% of computers into 1-5 random groups.
    participating_computers = rng.sample(computer_names, k=round(len(computer_names) * 0.1)) if computer_names else []
    for c in participating_computers:
        if not group_names:
            break
        for g in rng.sample(group_names, k=min(rng.randint(1, 5), len(group_names))):
            add(g, c, "computer")

    return memberships


def _generate_acl_noise(
    rng: random.Random, users: list[dict], groups: list[dict], computers: list[dict], ou_paths: list[str]
) -> list[dict]:
    """BadBlood's GenerateRandomPermissions.ps1 — the only permission family
    its own apply-loop actually invokes is GenericAll, granted to a random
    sample of users/groups/computers, mostly on a random OU, occasionally at
    the domain root."""
    noise = []

    def grant(pool: list[str], grantee_type: str) -> None:
        if not pool:
            return
        for grantee in rng.sample(pool, k=min(rng.randint(5, 100), len(pool))):
            at_root = rng.randint(1, 100) <= 5  # BadBlood: ~3-5%
            target = "domain_root" if at_root or not ou_paths else rng.choice(ou_paths)
            noise.append({"grantee": grantee, "grantee_type": grantee_type, "target": target, "right": "GenericAll"})

    grant([u["name"] for u in users], "user")
    grant([g["name"] for g in groups], "group")
    grant([c["name"] for c in computers], "computer")
    return noise


def generate_population_plan(
    theme: dict,
    population: dict,
    domain: str,
    seed_offset: int,
    user_count: int,
    group_count: int,
    computer_count: int,
    generate_password,
) -> dict:
    """Deterministic, full replacement for one domain's BadBlood run (users,
    groups, OUs, computers, memberships, ACL noise). `seed_offset` mirrors
    the existing per-domain badblood_seed trick (population.seed + domain
    index) so multi-domain labs don't draw identical populations twice.
    `generate_password` is forge's own generate_password — injected
    rather than imported, to keep this module dependency-free of forge."""
    rng = random.Random(population["seed"] + seed_offset)
    vocab = theme["vocabulary"]
    domain_dn = _domain_dn(domain)

    ous = _build_ou_tree(vocab["houses"], domain_dn)
    # Every OU's own full DN (what users/groups/computers actually get placed
    # *into*, as opposed to `path`, which is the DN of its *parent* container
    # — the shape community.windows.win_domain_ou itself expects).
    full_ou_dns = [f"OU={o['name']}," + o["path"] for o in ous]

    users = _generate_users(rng, user_count, vocab, full_ou_dns, generate_password)
    groups = _generate_groups(rng, group_count, full_ou_dns, [u["name"] for u in users], theme.get("extra_groups", []))
    computers = _generate_computers(rng, computer_count, vocab["houses"], [u["name"] for u in users])
    for c in computers:
        if c["ou"] is None:
            c["ou"] = rng.choice(full_ou_dns) if full_ou_dns else domain_dn
        elif c["ou"] == "Admin":
            c["ou"] = f"OU=Admin,{domain_dn}"
    for g in groups:
        if g["ou"] is None:
            # Curated groups sit at the domain root (matching today's
            # ad_theming_overlay behavior); non-curated ones without an OU
            # yet get a random placement, same as everything else.
            g["ou"] = domain_dn if g["curated"] else (rng.choice(full_ou_dns) if full_ou_dns else domain_dn)

    memberships = _generate_memberships(rng, users, groups, computers)
    acl_noise = (
        _generate_acl_noise(rng, users, groups, computers, full_ou_dns)
        if population.get("include_noise_acls", True)
        else []
    )
    for a in acl_noise:
        if a["target"] == "domain_root":
            a["target"] = domain_dn

    return {
        "domain": domain,
        "domain_dn": domain_dn,
        "ous": ous,
        "users": users,
        "groups": groups,
        "computers": computers,
        "memberships": memberships,
        "acl_noise": acl_noise,
    }
