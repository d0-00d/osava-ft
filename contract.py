"""
Shared rendering + normalisation for the classifier input contract.

One place that knows the frozen field order, the truncation rule, the EVTX
escaping rule, and -- critically -- the field-presence and identity policy
that keeps classes from being separable by anything except behaviour.

Used by gen_benign.py, gen_suspicious.py, and (retro-fitted) by the EVTX
converter so attack and synthetic events render through identical code.
"""

import hashlib
import random
import re

# R1: frozen field order. Absent fields are omitted entirely, never emitted
# as empty. Order is fixed so the model never sees a permuted contract.
FIELD_ORDER = [
    "EventID", "EventType", "Image", "CommandLine", "ParentImage",
    "ParentCommandLine", "User", "Signed", "Signer", "DestinationIp",
    "DestinationPort", "DestinationHostname", "TargetFilename",
    "LogonType", "AuthPackage",
]
KNOWN_FIELDS = set(FIELD_ORDER)

EVENT_TYPES = {
    1: "Process Create", 3: "Network Connection", 7: "Image Load",
    8: "Remote Thread", 10: "Process Access", 11: "File Create",
    12: "Registry Create", 13: "Registry Set", 22: "DNS Query",
    4624: "Logon", 4625: "Failed Logon", 4688: "Process Create",
    4697: "Service Install",
}

MAX_CMDLINE = 512
TRUNC_MARKER = "<truncated>"

# ---------------------------------------------------------------------------
# Identity pool.
#
# The attack corpus is 94x IEWIN7\IEUser and 75x MSEDGEWIN10\IEUser. Any
# synthetic class written with a different hostname is separable on hostname
# alone. Every class draws host and account from THIS pool, and retained
# attack events get rewritten through it too.
# ---------------------------------------------------------------------------
HOSTS = ["IEWIN7", "MSEDGEWIN10", "WKSTN-0143", "WKSTN-0271", "LAPTOP-JU4M3I0E",
         "FIN-WS-07", "DEV-WS-22", "PC01"]
SERVERS = ["ICORP-DC01", "ICORP-FS02", "ICORP-APP03", "WIN-77LTAPHIQ1R"]
LOCAL_USERS = ["IEUser", "bouss", "a-jbrown", "lgrove", "samir", "user01", "mchen"]
DOMAIN = "ICORP"
ADMINS = ["a-jbrown", "svc-deploy", "Administrator"]

SYSTEM_ACCOUNTS = [
    "NT AUTHORITY\\SYSTEM",
    "NT AUTHORITY\\LOCAL SERVICE",
    "NT AUTHORITY\\NETWORK SERVICE",
]

# ---------------------------------------------------------------------------
# Signature policy.
#
# OQ1 in the PRD. Rather than guess, both variants are generated from the same
# events and scored by the same harness:
#
#   mode="strip"    Signed/Signer omitted on every event in every class.
#                   Matches the attack corpus, which only carries them on
#                   EventID 7. Zero leak, loses a field production emits.
#   mode="backfill" Signed/Signer present on every process-create and image-load
#                   event in every class, derived from the image path by the
#                   rules below. Keeps the field, makes it non-discriminative.
#
# A280 (PsExec: validly signed by Microsoft, C:\Windows, services.exe parent)
# is the existence proof that signature status carries little discriminative
# weight. backfill is the honest test of that claim.
# ---------------------------------------------------------------------------
MS_SIGNER = "Microsoft Windows"
MS_CORP = "Microsoft Corporation"

VENDOR_SIGNERS = {
    "chrome.exe": "Google LLC", "GoogleUpdate.exe": "Google LLC",
    "firefox.exe": "Mozilla Corporation",
    "Code.exe": MS_CORP, "OneDrive.exe": MS_CORP, "Teams.exe": MS_CORP,
    "OUTLOOK.EXE": MS_CORP, "EXCEL.EXE": MS_CORP, "WINWORD.EXE": MS_CORP,
    "Update.exe": "Slack Technologies, LLC", "slack.exe": "Slack Technologies, LLC",
    "NVIDIA Web Helper.exe": "NVIDIA Corporation",
    "Dropbox.exe": "Dropbox, Inc", "7zG.exe": "Igor Pavlov",
    "PsExec.exe": MS_CORP, "PsExec64.exe": MS_CORP, "PSEXESVC.exe": MS_CORP,
    "python.exe": "Python Software Foundation",
    "node.exe": "OpenJS Foundation",
    "AcroRd32.exe": "Adobe Inc.",
    "AnyDesk.exe": "AnyDesk Software GmbH",
    "TeamViewer.exe": "TeamViewer Germany GmbH",
    "putty.exe": "Simon Tatham", "plink.exe": "Simon Tatham",
    "7z.exe": "Igor Pavlov", "ProcessHacker.exe": "Winsider Seminars & Solutions Inc.",
}

SYSTEM_DIRS = ("c:\\windows\\system32", "c:\\windows\\syswow64",
               "c:\\windows\\winsxs", "c:\\program files", "c:\\program files (x86)")

# Inside C:\Windows but writable by unprivileged users, so "under Windows"
# does not imply "shipped with Windows". Backfilling these as signed would
# assert a false fact about exactly the technique the model must catch:
# dropping a payload into a system-adjacent path.
WRITABLE_WINDOWS_DIRS = ("c:\\windows\\temp", "c:\\windows\\tasks",
                         "c:\\windows\\debug", "c:\\windows\\tracing",
                         "c:\\windows\\registration\\crmlog",
                         "c:\\windows\\system32\\spool\\drivers\\color",
                         "c:\\windows\\system32\\tasks")


def signature_for(image):
    """(Signed, Signer) derived from the image path. None means unknowable.

    Deliberately mechanical: anything under a Windows or Program Files path is
    treated as validly signed, which is exactly why PsExec dropped into
    C:\\Windows scores as signed Microsoft -- the A280 case."""
    if not image:
        return None
    low = image.lower()
    base = image.rsplit("\\", 1)[-1]
    if base in VENDOR_SIGNERS:
        return ("true", VENDOR_SIGNERS[base])
    if low.startswith(WRITABLE_WINDOWS_DIRS) or low.startswith("c:\\users\\public"):
        return ("false", None)
    if low.startswith(SYSTEM_DIRS) or low.startswith("c:\\windows\\"):
        return ("true", MS_SIGNER)
    # user-writable paths: unsigned unless the caller says otherwise
    return ("false", None)


def apply_signature(fields, mode):
    """Enforce the chosen signature policy uniformly across classes."""
    if mode == "strip":
        fields.pop("Signed", None)
        fields.pop("Signer", None)
        return fields
    if mode != "backfill":
        raise ValueError(f"unknown signature mode {mode!r}")
    if int(fields["EventID"]) not in (1, 7, 4688):
        fields.pop("Signed", None)
        fields.pop("Signer", None)
        return fields
    if "Signed" not in fields:
        sig = signature_for(fields.get("Image"))
        if sig:
            fields["Signed"] = sig[0]
            if sig[1]:
                fields["Signer"] = sig[1]
    return fields


# ---------------------------------------------------------------------------
# Normalisation (R3)
# ---------------------------------------------------------------------------
def normalise_cmdline(s):
    """EVTX doubles '%' in rendered message text; undo it, then truncate with
    an explicit marker rather than a bare ellipsis."""
    s = s.replace("%%", "%")
    if len(s) > MAX_CMDLINE:
        s = s[:MAX_CMDLINE] + TRUNC_MARKER
    return s


def render(fields, sig_mode="backfill"):
    """dict -> the frozen `Key: value` block."""
    f = dict(fields)
    eid = int(f["EventID"])
    f.setdefault("EventType", EVENT_TYPES[eid])
    for k in ("CommandLine", "ParentCommandLine"):
        if k in f:
            f[k] = normalise_cmdline(str(f[k]))
    f = apply_signature(f, sig_mode)
    unknown = set(f) - KNOWN_FIELDS
    if unknown:
        raise ValueError(f"off-contract fields: {sorted(unknown)}")
    return "\n".join(f"{k}: {f[k]}" for k in FIELD_ORDER if k in f and f[k] is not None)


def stable_rng(seed_str):
    """Deterministic per-template RNG so regenerating the set is reproducible."""
    h = hashlib.sha256(seed_str.encode()).hexdigest()
    return random.Random(int(h[:16], 16))


# ---------------------------------------------------------------------------
# EventID mix.
#
# Measured over the 500-event attack pool. Synthetic classes are sampled to
# this shape so EventID is not itself a class signal.
# ---------------------------------------------------------------------------
ATTACK_EID_MIX = {1: 0.514, 13: 0.130, 11: 0.122, 3: 0.080,
                  4624: 0.068, 7: 0.050, 12: 0.032, 4625: 0.002}


def eid_target_counts(n, mix=None):
    """How many events of each EventID to hit the measured mix at size n."""
    mix = mix or ATTACK_EID_MIX
    raw = {k: v * n for k, v in mix.items()}
    out = {k: int(v) for k, v in raw.items()}
    rem = n - sum(out.values())
    for k in sorted(raw, key=lambda k: -(raw[k] - out[k])):
        if rem <= 0:
            break
        out[k] += 1
        rem -= 1
    return out


def validate(body):
    """Contract check: known fields only, correct order, no empties."""
    errs = []
    seen = []
    for line in body.splitlines():
        if ":" not in line:
            errs.append(f"no colon: {line!r}")
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        if k not in KNOWN_FIELDS:
            errs.append(f"off-contract field {k!r}")
        if not v.strip():
            errs.append(f"empty value for {k!r}")
        seen.append(k)
    idx = [FIELD_ORDER.index(k) for k in seen if k in KNOWN_FIELDS]
    if idx != sorted(idx):
        errs.append(f"field order violated: {seen}")
    if len(set(seen)) != len(seen):
        errs.append(f"duplicate fields: {seen}")
    return errs


# ---------------------------------------------------------------------------
# Shared parent and identity pools.
#
# The first audit pass found cmd.exe parenting 69% of the suspicious class and
# explorer.exe/svchost.exe parenting only benign events -- the model would have
# learned the parent name, not the behaviour. Any family without a
# semantically-required parent draws from this shared pool instead, so parent
# process is uninformative across classes.
# ---------------------------------------------------------------------------
PARENT_GROUPS = {
    # a human at a keyboard, or a script they launched
    "interactive": [
        ("C:\\Windows\\System32\\cmd.exe", '"C:\\Windows\\System32\\cmd.exe"'),
        ("C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"'),
        ("C:\\Windows\\System32\\cmd.exe",
         '"C:\\Windows\\System32\\cmd.exe" /s /k pushd "C:\\Users\\Public"'),
        ("C:\\Windows\\System32\\mmc.exe",
         '"C:\\Windows\\system32\\mmc.exe" "C:\\Windows\\system32\\compmgmt.msc"'),
        ("C:\\Users\\IEUser\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
         '"C:\\Users\\IEUser\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe" --type=terminal'),
    ],
    # a job the machine runs on its own schedule or at logon
    "scheduled": [
        ("C:\\Windows\\System32\\taskeng.exe",
         'taskeng.exe {A1B2C3D4-0000-0000-0000-000000000001} S-1-5-18:NT AUTHORITY\\System:Service:'),
        ("C:\\Windows\\System32\\svchost.exe",
         "C:\\Windows\\system32\\svchost.exe -k netsvcs"),
        ("C:\\Windows\\System32\\cmd.exe",
         '"C:\\Windows\\System32\\cmd.exe" /c C:\\ProgramData\\ICORP\\logon.bat'),
    ],
    # the SCM or a COM/WMI host starting something
    "service": [
        ("C:\\Windows\\System32\\services.exe", "C:\\Windows\\system32\\services.exe"),
        ("C:\\Windows\\System32\\svchost.exe",
         "C:\\Windows\\system32\\svchost.exe -k DcomLaunch"),
        ("C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
         "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding"),
    ],
}
SHELL_PARENTS = [p for g in PARENT_GROUPS.values() for p in g]


def pick_parent(r, groups=("interactive", "scheduled")):
    """Parent process drawn from a class-independent pool.

    `groups` narrows it to lineages that are plausible for the family, so that
    varying the parent does not silently change the event's true label -- a
    services.exe parent on a download cradle is not a milder version of the
    same event, it is a different, worse one."""
    pool = [p for g in groups for p in PARENT_GROUPS[g]]
    return r.choice(pool)


# Account kinds are drawn from the SAME distribution in every class. Domain
# accounts and the ICORP realm must appear on both sides or the domain name
# itself becomes the label.
ACCOUNT_KINDS = ["local", "local", "local", "domain", "domain", "admin", "system"]


def pick_account(r, kind=None):
    kind = kind or r.choice(ACCOUNT_KINDS)
    if kind == "system":
        return r.choice(SYSTEM_ACCOUNTS)
    if kind == "admin":
        return f"{DOMAIN}\\{r.choice(ADMINS)}"
    if kind == "domain":
        return f"{DOMAIN}\\{r.choice(LOCAL_USERS)}"
    return f"{r.choice(HOSTS)}\\{r.choice(LOCAL_USERS)}"


def home_of(user):
    return f"C:\\Users\\{user.split(chr(92))[-1]}"
