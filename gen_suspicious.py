"""
Suspicious class generator (gold = suspicious, severity medium).

Addresses the PRD's "suspicious class never fires" risk. Both baseline runs
predicted zero suspicious and put zero mass on `medium`; the class has no
training signal because nothing in the corpus occupies it.

The defining property of this class is NOT "a weak attack". It is an event
whose technique surface is identical to the malicious class but whose context
is genuinely ambiguous -- admin tooling doing admin-shaped work, LOLBins
pointed at internal infrastructure, enumeration that is either an inventory
script or the first ten minutes of an intrusion. These are exactly the events
the escalation tier exists to adjudicate. If the classifier could resolve them
confidently it would not need a second tier.

    python3 gen_suspicious.py --n 30 --out suspicious_events --sig backfill
"""

import argparse
import json
from pathlib import Path

from contract import (ADMINS, DOMAIN, HOSTS, LOCAL_USERS, SERVERS, home_of,
                      eid_target_counts, pick_account, pick_parent, render,
                      stable_rng, validate)

SYS32 = "C:\\Windows\\System32"
PS = f"{SYS32}\\WindowsPowerShell\\v1.0\\powershell.exe"


def _u(r):
    """Account drawn from the shared cross-class distribution."""
    user = pick_account(r, r.choice(["local", "local", "domain"]))
    return user.split(chr(92))[0], user


def _admin(r):
    return f"{DOMAIN}\\{r.choice(ADMINS)}"


def _home(user):
    return f"C:\\Users\\{user.split(chr(92))[-1]}"


# --------------------------------------------------------------------------
# EventID 1 -- Process Create
# --------------------------------------------------------------------------
def s_discovery(r):
    """T1033/T1069/T1018/T1082. The single most common genuinely-ambiguous
    event class: an inventory script and an intruder run identical commands."""
    _p = pick_parent(r)
    cmd, attck, why = r.choice([
        (f'"{SYS32}\\whoami.exe" /all', "T1033",
         "whoami /all dumps groups and privileges; run by helpdesk scripts and "
         "by operators establishing context"),
        (f'"{SYS32}\\net.exe" group "Domain Admins" /domain', "T1069.002",
         "privileged group enumeration against the domain"),
        (f'"{SYS32}\\nltest.exe" /dclist:icorp.local', "T1018",
         "domain controller enumeration"),
        (f'"{SYS32}\\systeminfo.exe"', "T1082",
         "full host inventory including hotfix level"),
        (f'"{SYS32}\\net.exe" localgroup administrators', "T1069.001",
         "local admin group membership"),
        ('powershell.exe -Command "Get-ADComputer -Filter * | Select Name"', "T1018",
         "domain-wide host enumeration via AD module"),
        (f'"{SYS32}\\quser.exe"', "T1033",
         "enumerating other logged-on sessions on the host"),
    ])
    host, user = _u(r)
    img = PS if cmd.startswith("powershell") else cmd.split('"')[1]
    return dict(EventID=1, Image=img, CommandLine=cmd, ParentImage=_p[0], ParentCommandLine=_p[1], User=user), \
        ("host/domain enumeration", attck,
         why + " -- benign under an inventory job, malicious under an intrusion; "
         "the event alone does not distinguish them")


def s_remote_admin(r):
    """T1021.002. PsExec run interactively by an admin. A280 is the SYSTEM-side
    service artefact of this and is malicious; the operator-side invocation by
    a named admin account is genuinely ambiguous."""
    _p = pick_parent(r, groups=("interactive",))
    admin = _admin(r)
    host = r.choice(SERVERS)
    home = f"C:\\Users\\{admin.split(chr(92))[-1]}"
    img, cmd, attck, why = r.choice([
        (f"{home}\\Downloads\\PsExec64.exe",
         f'PsExec64.exe \\\\{host} -s cmd.exe /c "sc query"', "T1021.002",
         "PsExec to a server as SYSTEM -- the -s flag is what separates routine "
         "remote administration from lateral movement, and both use it"),
        (f"{SYS32}\\wbem\\WMIC.exe",
         f'wmic /node:{host} process call create "cmd.exe /c ipconfig /all"', "T1047",
         "remote process creation over WMI; a real management pattern and a "
         "standard lateral-movement primitive"),
        (f"{SYS32}\\net.exe", f"net use \\\\{host}\\ADMIN$ /user:{admin} *", "T1021.002",
         "admin share mount -- required for legitimate remote deployment and for "
         "payload staging"),
        (PS, f'powershell.exe -Command "Invoke-Command -ComputerName {host} '
             '-ScriptBlock {Get-Process}"', "T1021.006",
         "WinRM remote execution"),
    ])
    return dict(EventID=1, Image=img, CommandLine=cmd, ParentImage=_p[0], ParentCommandLine=_p[1], User=admin), \
        ("remote administration", attck, why)


def s_internal_fetch(r):
    """Download cradle pointed at internal infrastructure. Same primitive as
    the malicious class; the destination is the only difference."""
    _p = pick_parent(r, groups=("interactive",))
    host, user = _u(r)
    server, cmd, attck, why = r.choice([
        ("artifacts.icorp.local",
         'powershell.exe -Command "Invoke-WebRequest -Uri '
         'http://artifacts.icorp.local/agent/install.ps1 -OutFile C:\\Windows\\Temp\\install.ps1"',
         "T1105", "remote-fetch to a Temp path -- internal host, but the pattern "
                  "is the download half of a cradle"),
        ("deploy.icorp.local",
         f'"{SYS32}\\certutil.exe" -urlcache -split -f '
         "http://deploy.icorp.local/pkg/setup.msi C:\\Windows\\Temp\\setup.msi",
         "T1105", "certutil as a downloader; a documented LOLBin technique used "
                  "here against an internal artifact server"),
        ("fs02.icorp.local",
         'powershell.exe -ExecutionPolicy Bypass -File \\\\fs02.icorp.local\\scripts\\'
         'inventory.ps1', "T1059.001",
         "policy bypass executing a script from a domain file share"),
    ])
    img = PS if cmd.startswith("powershell") else f"{SYS32}\\certutil.exe"
    return dict(EventID=1, Image=img, CommandLine=cmd, ParentImage=_p[0], ParentCommandLine=_p[1], User=user), \
        ("internal remote fetch", attck, why)


def s_persistence_grey(r):
    """Scheduled task / service creation outside an installer context."""
    _p = pick_parent(r, groups=("interactive",))
    host, user = _u(r)
    admin = _admin(r)
    cmd, acct, attck, why = r.choice([
        (f'"{SYS32}\\schtasks.exe" /create /sc daily /st 03:00 /tn "ICORP-Inventory" '
         '/tr "powershell.exe -File C:\\ProgramData\\ICORP\\inv.ps1" /ru SYSTEM',
         admin, "T1053.005",
         "daily SYSTEM task running a PowerShell script from ProgramData -- the "
         "shape of scripted persistence and of a real inventory job"),
        (f'"{SYS32}\\sc.exe" create ICORPAgent binPath= '
         '"C:\\ProgramData\\ICORP\\agent.exe" start= auto',
         admin, "T1543.003",
         "service created pointing at a ProgramData binary; management agents "
         "install exactly this way"),
        (f'"{SYS32}\\reg.exe" add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
         '/v Updater /t REG_SZ /d "C:\\ProgramData\\ICORP\\upd.exe" /f',
         user, "T1547.001",
         "Run key written by reg.exe rather than by an installer"),
    ])
    img = f"{SYS32}\\{cmd.split(chr(92))[3].split('.exe')[0]}.exe" if False else \
        cmd.split('"')[1]
    return dict(EventID=1, Image=img, CommandLine=cmd, ParentImage=_p[0], ParentCommandLine=_p[1], User=acct), \
        ("persistence mechanism created", attck, why)


def s_staging(r):
    """T1560. Bulk archiving of user data -- backup or exfil staging."""
    _p = pick_parent(r)
    host, user = _u(r)
    home = _home(user)
    img, cmd, why = r.choice([
        ("C:\\Program Files\\7-Zip\\7z.exe",
         f'"C:\\Program Files\\7-Zip\\7z.exe" a -tzip -mx1 C:\\Windows\\Temp\\d.zip '
         f'"{home}\\Documents\\*"',
         "user documents archived into Windows\\Temp -- a backup habit and an "
         "exfil-staging step look the same at this layer"),
        (PS,
         'powershell.exe -Command "Compress-Archive -Path '
         f'{home}\\Documents\\* -DestinationPath C:\\Windows\\Temp\\docs.zip"',
         "same pattern via the PowerShell built-in"),
    ])
    return dict(EventID=1, Image=img, CommandLine=cmd, ParentImage=_p[0], ParentCommandLine=_p[1], User=user), \
        ("bulk archive to Temp", "T1560.001", why)


def s_shadow_recon(r):
    _p = pick_parent(r)
    host, user = _u(r)
    cmd, attck, why = r.choice([
        (f'"{SYS32}\\vssadmin.exe" list shadows', "T1490",
         "listing shadow copies -- read-only, but it is the reconnaissance step "
         "ransomware performs before deleting them"),
        (f'"{SYS32}\\reg.exe" query "HKLM\\SYSTEM\\CurrentControlSet\\Services" /s /f ImagePath',
         "T1007", "service configuration sweep"),
        (f'"{SYS32}\\netstat.exe" -ano', "T1049",
         "full connection table with owning PIDs"),
    ])
    return dict(EventID=1, Image=cmd.split('"')[1], CommandLine=cmd,
                ParentImage=_p[0], ParentCommandLine=_p[1], User=user), \
        ("pre-impact reconnaissance", attck, why)


def s_account_admin(r):
    _p = pick_parent(r, groups=("interactive",))
    admin = _admin(r)
    cmd, attck, why = r.choice([
        (f'"{SYS32}\\net.exe" user svc-backup Wint3r2026! /add /domain', "T1136.002",
         "domain account creation from a command line rather than a directory tool"),
        (f'"{SYS32}\\net.exe" localgroup administrators helpdesk /add', "T1098",
         "local administrator group addition"),
    ])
    return dict(EventID=1, Image=f"{SYS32}\\net.exe", CommandLine=cmd,
                ParentImage=_p[0], ParentCommandLine=_p[1], User=admin), \
        ("account manipulation", attck, why)


# --------------------------------------------------------------------------
# EventID 3 -- Network Connection
# --------------------------------------------------------------------------
def s_network(r):
    host, user = _u(r)
    home = _home(user)
    img, ip, port, dns, attck, why = r.choice([
        (PS, "104.21.63.190", 8443, None, "T1071.001",
         "PowerShell opening a TLS-alt port to a public IP with no preceding DNS "
         "resolution"),
        (f"{home}\\AppData\\Local\\Programs\\Python\\Python311\\python.exe",
         "159.65.20.14", 8888, None, "T1571",
         "interpreter to a non-standard high port on a hosting-provider range"),
        (f"{SYS32}\\mstsc.exe", "203.0.113.44", 3389, None, "T1021.001",
         "outbound RDP to a public address -- jump-box access or an operator "
         "hopping outward"),
        (f"{SYS32}\\cmd.exe", "10.14.7.33", 445, "ICORP-FS02.icorp.local", "T1021.002",
         "SMB from a command shell rather than from the redirector"),
    ])
    f = dict(EventID=3, Image=img, User=user, DestinationIp=ip, DestinationPort=port)
    if dns:
        f["DestinationHostname"] = dns
    return f, ("anomalous outbound connection", attck, why)


# --------------------------------------------------------------------------
# EventID 11 / 12 / 13
# --------------------------------------------------------------------------
def s_file(r):
    host, user = _u(r)
    home = _home(user)
    img, tgt, attck, why = r.choice([
        (PS, "C:\\ProgramData\\ICORP\\inv.ps1", "T1105",
         "script written to ProgramData by an interpreter rather than an installer"),
        (f"{SYS32}\\cmd.exe", "C:\\Windows\\Temp\\svc.exe", "T1105",
         "executable written to Windows\\Temp by a shell -- staging, but no "
         "execution or network context in this event to confirm intent"),
        (f"{home}\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
         f"{home}\\Downloads\\PsExec64.exe", "T1105",
         "administration tool downloaded via a browser"),
    ])
    return dict(EventID=11, Image=img, TargetFilename=tgt), \
        ("staged file write", attck, why)


def s_registry(r):
    img, tgt, attck, why = r.choice([
        (f"{SYS32}\\reg.exe",
         "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ICORPUpdater",
         "T1547.001", "Run key written by reg.exe with no installer in the lineage"),
        (f"{SYS32}\\services.exe",
         "HKLM\\System\\CurrentControlSet\\Services\\ICORPAgent\\ImagePath",
         "T1543.003", "new service image path -- indistinguishable from A306 "
                      "except that the service name is a plausible internal one"),
        (PS,
         "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\ProgramData\\ICORP",
         "T1562.001", "Defender path exclusion added by PowerShell -- a real "
                      "deployment step and a standard evasion step"),
        (f"{SYS32}\\reg.exe",
         "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections",
         "T1021.001", "RDP being enabled from the command line"),
    ])
    return dict(EventID=13, Image=img, TargetFilename=tgt), \
        ("grey-area registry change", attck, why)


# --------------------------------------------------------------------------
# EventID 4624 / 4625 -- Logon
# --------------------------------------------------------------------------
def s_logon(r):
    admin = _admin(r)
    host, user = _u(r)
    who, lt, pkg, ip, attck, why = r.choice([
        (admin, 3, "NTLM", "10.14.9.87", "T1078.002",
         "domain admin authenticating over NTLM from a workstation subnet rather "
         "than Kerberos from a management host"),
        (user, 10, "Negotiate", "10.14.9.203", "T1021.001",
         "RDP session from a peer workstation rather than from IT"),
        (f"{DOMAIN}\\svc-deploy", 3, "NTLM", "10.14.7.33", "T1078.003",
         "service account performing an interactive-shaped network logon"),
        (user, 9, "Negotiate", None, "T1134.003",
         "NewCredentials logon -- explicit alternate credentials, the runas "
         "pattern"),
    ])
    f = dict(EventID=4624, User=who, LogonType=lt, AuthPackage=pkg)
    if ip:
        f["DestinationIp"] = ip
    return f, ("anomalous logon", attck, why)


def s_failed_logon(r):
    host, user = _u(r)
    return dict(EventID=4625, User=f"{DOMAIN}\\Administrator", LogonType=3,
                AuthPackage="NTLM", DestinationIp="10.14.9.212"), \
        ("failed administrator logon", "T1110",
         "single failed NTLM network logon for a privileged account -- a typo or "
         "the first of a spray; one event cannot tell")


def s_dualuse_tool(r):
    """Signed, Program Files, third-party -- and squarely dual-use. Remote
    access and tunnelling suites are deployed by IT and by intruders, often the
    same build. Nothing about the binary resolves it; only who authorised it."""
    _p = pick_parent(r, groups=("interactive",))
    user = _u(r)[1]
    img, cmd, attck, why = r.choice([
        ("C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe",
         '"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe" --start-service', "T1219",
         "remote access software installed as a service; standard for support "
         "desks and a first-choice persistence channel for intruders"),
        ("C:\\Program Files\\PuTTY\\plink.exe",
         'plink.exe -ssh -R 3389:127.0.0.1:3389 svc@10.14.7.33 -pw ****', "T1572",
         "reverse SSH port forward exposing RDP -- a legitimate jump-host "
         "pattern and a tunnelling primitive"),
        ("C:\\Program Files\\TeamViewer\\TeamViewer.exe",
         '"C:\\Program Files\\TeamViewer\\TeamViewer.exe" --unattended', "T1219",
         "unattended remote access enabled on a workstation"),
        ("C:\\Program Files\\Process Hacker 2\\ProcessHacker.exe",
         '"C:\\Program Files\\Process Hacker 2\\ProcessHacker.exe"', "T1057",
         "signed process inspection tool with driver-level access; used by "
         "engineers and for credential access alike"),
    ])
    return dict(EventID=1, Image=img, CommandLine=cmd, ParentImage=_p[0],
                ParentCommandLine=_p[1], User=user), \
        ("dual-use administration tool", attck, why)


def s_unsigned_tool(r):
    """Unsigned binary in a user-writable path -- but doing something a real
    admin does. Shares `Signed: false` with the malicious class so the field
    cannot carry the decision on its own."""
    _p = pick_parent(r, groups=("interactive",))
    user = _u(r)[1]
    home = home_of(user)
    img, cmd, attck, why = r.choice([
        (f"{home}\\Downloads\\nmap.exe", 'nmap.exe -sS -p 1-1024 10.14.7.0/24',
         "T1046", "network service scan from a workstation; the security team "
                  "does this on a schedule and so does an intruder on day one"),
        (f"{home}\\Downloads\\adfind.exe", 'adfind.exe -f "objectcategory=user" -dn',
         "T1087.002", "directory enumeration utility -- an auditing staple and "
                      "a fixture of ransomware intrusions"),
        ("C:\\ProgramData\\ICORP\\deploy\\push.exe",
         'push.exe /targets:servers.txt /cmd:"gpupdate /force"',
         "T1072", "unsigned in-house deployment tool executing across a host "
                  "list; the mechanism is indistinguishable from a deployment "
                  "system being abused"),
    ])
    return dict(EventID=1, Image=img, CommandLine=cmd, ParentImage=_p[0],
                ParentCommandLine=_p[1], User=user, Signed="false"), \
        ("unsigned administrative tooling", attck, why)


FAMILIES = {
    1: [s_discovery, s_dualuse_tool, s_unsigned_tool, s_remote_admin, s_internal_fetch, s_persistence_grey,
        s_staging, s_shadow_recon, s_account_admin],
    3: [s_network],
    11: [s_file],
    12: [s_registry],
    13: [s_registry],
    4624: [s_logon],
    4625: [s_failed_logon],
    7: [],
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--out", default="suspicious_events")
    ap.add_argument("--prefix", default="S")
    ap.add_argument("--sig", choices=["backfill", "strip"], default="backfill")
    ap.add_argument("--seed", default="osava-susp-v1")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob(f"{args.prefix}*.txt"):
        old.unlink()

    targets = eid_target_counts(args.n)
    # EventID 7 has no suspicious analogue worth writing (a signed system DLL
    # loading is either normal or is sideloading, which is malicious); its
    # share is folded into EventID 1.
    targets[1] += targets.pop(7, 0)

    rows, bodies, n = [], set(), 0
    labels = {}

    for eid, want in sorted(targets.items()):
        fams = FAMILIES.get(eid, [])
        if not fams or want == 0:
            continue
        got, tries = 0, 0
        while got < want and tries < want * 60:
            tries += 1
            fn = fams[tries % len(fams)]
            r = stable_rng(f"{args.seed}|{eid}|{fn.__name__}|{tries}")
            fields, (name, attck, why) = fn(r)
            body = render(fields, sig_mode=args.sig)
            if body in bodies:
                continue
            errs = validate(body)
            if errs:
                raise SystemExit(f"{fn.__name__}: {errs}")
            bodies.add(body)
            n += 1
            got += 1
            sid = f"{args.prefix}{n:03d}"
            (out / f"{sid}.txt").write_text(body + "\n")
            labels[sid] = (name, "suspicious", "medium", why)
            rows.append("\t".join([sid, "synthetic:gen_suspicious.py", str(eid),
                                   fn.__name__, "medium", attck or "-", why]))

    (out / "manifest.tsv").write_text(
        "file\tsource\tevent_id\tfamily\tseverity\tattck\trationale\n"
        + "\n".join(rows) + "\n")
    (out / "labels.json").write_text(json.dumps(labels, indent=2))
    print(f"wrote {n} suspicious events to {out}/  (sig={args.sig})")
    print("eid mix:", {k: v for k, v in sorted(targets.items()) if v})
    fam = {}
    for row in rows:
        f = row.split("\t")[3]
        fam[f] = fam.get(f, 0) + 1
    print("families:", fam)


if __name__ == "__main__":
    main()
