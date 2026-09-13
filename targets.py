"""
Derive the full output object for a training row.

train_final.jsonl carries a severity and a `provenance.rationale`, but the
rationale is a *provenance* note ("unique to this capture", "appears in 4
captures") -- a statement about the corpus, not about the event. 808 of 1993
rows say exactly that. Training a classifier to emit it would teach the model
to justify itself with a fact it cannot observe at inference time, and one
that correlates with the label. So reasoning is regenerated here, from the
event alone.

Everything below is a function of the rendered event text and nothing else.
That is the property that matters: at inference the model sees the same input
this file sees, so every field of the target is in principle derivable. The
one exception is `severity`, which comes from the label -- the model has to
learn the judgment, and the judgment is deliberately NOT a function of the
indicators (a signed vendor binary in AppData is benign; an unsigned one in
Temp is not; both emit `unsigned_binary`-adjacent evidence).

Indicator keys come from indicators.INDICATORS (R6, closed vocabulary).
Values are quoted evidence lifted from the event, which is what the shipped
HIRA schema's `{"key": "value"}` shape is for.
"""

import re

from indicators import INDICATORS

# ---------------------------------------------------------------- vocab

LOLBINS = {
    "rundll32.exe", "mshta.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "cscript.exe", "wscript.exe", "msbuild.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "cmstp.exe", "forfiles.exe", "pcalua.exe",
    "odbcconf.exe", "xwizard.exe", "presentationhost.exe", "ieexec.exe",
    "msdt.exe", "hh.exe", "ftp.exe", "esentutl.exe", "extrac32.exe",
    "makecab.exe", "expand.exe", "replace.exe", "print.exe", "scriptrunner.exe",
    "mavinject.exe", "sc.exe", "schtasks.exe", "at.exe", "reg.exe",
}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
          "mshta.exe", "bash.exe", "wsl.exe"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
          "msaccess.exe", "mspub.exe", "visio.exe", "onenote.exe"}
BROWSERS = {"chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
            "brave.exe", "opera.exe", "vivaldi.exe"}
SERVICE_HOSTS = {"services.exe", "svchost.exe"}
# names a payload borrows to hide in a process list
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "services.exe", "csrss.exe",
                "winlogon.exe", "smss.exe", "spoolsv.exe", "taskhostw.exe",
                "dllhost.exe", "conhost.exe", "wininit.exe", "explorer.exe",
                "runtimebroker.exe", "sihost.exe", "ctfmon.exe"}

SYSTEM_DIRS = ("c:\\windows\\system32", "c:\\windows\\syswow64",
               "c:\\program files", "c:\\program files (x86)",
               "c:\\windows\\winsxs", "c:\\windows\\microsoft.net")
# writable-by-user locations. \windows\temp is writable despite living under
# \windows, which is the whole reason contract.WRITABLE_WINDOWS_DIRS exists.
TEMP_DIRS = ("\\appdata\\local\\temp", "\\appdata\\roaming", "\\appdata\\local",
             "c:\\windows\\temp", "c:\\programdata", "c:\\temp", "c:\\users\\public",
             "\\downloads", "c:\\perflogs", "c:\\windows\\tasks",
             "c:\\windows\\debug", "c:\\windows\\tracing")

# parent -> children that are unremarkable for it
EXPECTED = {
    "explorer.exe": {"cmd.exe", "powershell.exe", "notepad.exe", "chrome.exe",
                     "msedge.exe", "firefox.exe", "code.exe", "winword.exe",
                     "excel.exe", "outlook.exe", "teams.exe", "slack.exe",
                     "mmc.exe", "taskmgr.exe", "control.exe", "regedit.exe"},
    "services.exe": {"svchost.exe", "spoolsv.exe", "msmpeng.exe", "searchindexer.exe",
                     "wmiprvse.exe", "vmtoolsd.exe", "sqlservr.exe", "w3wp.exe",
                     "dllhost.exe", "vgauthservice.exe", "securityhealthservice.exe"},
    "svchost.exe": {"taskhostw.exe", "runtimebroker.exe", "sihost.exe", "ctfmon.exe",
                    "dllhost.exe", "wmiprvse.exe", "audiodg.exe", "consent.exe",
                    "backgroundtaskhost.exe", "wuauclt.exe", "usoclient.exe"},
    "wininit.exe": {"services.exe", "lsass.exe", "lsm.exe"},
    "userinit.exe": {"explorer.exe"},
    "winlogon.exe": {"userinit.exe", "dwm.exe", "logonui.exe", "fontdrvhost.exe"},
    "taskeng.exe": {"cmd.exe", "powershell.exe", "msiexec.exe"},
    "msiexec.exe": {"msiexec.exe", "rundll32.exe"},
    "code.exe": {"code.exe", "cmd.exe", "powershell.exe", "node.exe", "git.exe"},
}

RE_HIDDEN = re.compile(r"(?i)(-w(?:indow)?s?(?:tyle)?\s+h(?:idden)?\b|"
                       r"createnowindow|\bwindowstyle\s*=\s*hidden)")
RE_ENCODED = re.compile(r"(?i)(-e(?:nc|ncoded)?(?:command)?\s+[A-Za-z0-9+/=]{16,}|"
                        r"frombase64string|\[convert\]::|-enc\b|-encodedcommand\b)")
RE_CRADLE = re.compile(r"(?i)(invoke-webrequest|invoke-restmethod|\biwr\b|\bcurl\b|"
                       r"\bwget\b|downloadstring|downloadfile|downloaddata|"
                       r"net\.webclient|start-bitstransfer|bitsadmin[^|]*?/transfer|"
                       r"certutil[^|]*?-urlcache|\bhttps?://)")
RE_BYPASS = re.compile(r"(?i)(-ex(?:ec)?(?:utionpolicy)?\s+(bypass|unrestricted)|"
                       r"-nop\b|-noprofile\b)")
RE_DISCOVERY = re.compile(r"(?i)\b(whoami|systeminfo|nltest|net\s+(user|group|"
                          r"localgroup|view|share|accounts)|net1\s+(user|group)|"
                          r"ipconfig|arp\s+-a|nbtstat|quser|qwinsta|dsquery|"
                          r"tasklist|hostname|netstat|route\s+print|"
                          r"wmic\s+(computersystem|os|process|qfe|useraccount))\b")
RE_CRED = re.compile(r"(?i)(sekurlsa|logonpasswords|lsass|mimikatz|ntds\.dit|"
                     r"\bsam\b\s+save|reg\s+save\s+hk\w*\\+(sam|security|system)|"
                     r"comsvcs\.dll[^|]*?minidump|vaultcmd|dpapi)")
RE_ADMIN_SHARE = re.compile(r"(?i)\\\\[^\\]+\\(admin\$|ipc\$|c\$)")
RE_IP = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# HKLM\...\Run, Winlogon shell/userinit, service ImagePath, IFEO debugger
RE_AUTORUN = re.compile(r"(?i)(\\currentversion\\run(once)?\b|\\winlogon\\(shell|userinit)|"
                        r"\\image file execution options\\|\\services\\[^\\]+\\imagepath|"
                        r"\\currentversion\\explorer\\shell\s?folders|"
                        r"\\policies\\explorer\\run|\\userinitmprlogonscript)")
RE_ANTIFOREN = re.compile(r"(?i)(vssadmin[^|]*?delete\s+shadows|wevtutil\s+cl|"
                          r"clear-eventlog|bcdedit[^|]*?(recoveryenabled|bootstatuspolicy)|"
                          r"wbadmin\s+delete|cipher\s+/w|fsutil\s+usn\s+deletejournal)")

# ---------------------------------------------------------------- parsing

_KEY = re.compile(r"^([A-Za-z][A-Za-z0-9_]*): ?(.*)$")


def parse(event):
    """Rendered `Key: value` body back into a dict, tolerating wrapped values."""
    fields, last = {}, None
    for line in event.split("\n"):
        m = _KEY.match(line)
        if m:
            last = m.group(1)
            fields[last] = m.group(2)
        elif last is not None:
            fields[last] += "\n" + line
    return fields


def _base(p):
    return p.replace("/", "\\").rsplit("\\", 1)[-1].lower() if p else ""


def _dir(p):
    p = (p or "").replace("/", "\\")
    return p.rsplit("\\", 1)[0].lower() if "\\" in p else ""


def _in(d, prefixes):
    return any(x in d for x in prefixes)


def _clip(v, n=120):
    v = " ".join(str(v).split())
    return v if len(v) <= n else v[: n - 1] + "\u2026"

# ---------------------------------------------------------------- indicators


def extract(fields):
    """Ordered {indicator: evidence}. Incriminating first, exculpatory last --
    the model reads its own output left to right when it writes `reasoning`."""
    eid = str(fields.get("EventID", ""))
    img = fields.get("Image", "")
    par = fields.get("ParentImage", "")
    cmd = fields.get("CommandLine", "")
    tgt = fields.get("TargetFilename", "") or fields.get("TargetObject", "")
    user = fields.get("User", "") or fields.get("TargetUser", "")
    signed = str(fields.get("Signed", "")).lower()
    signer = fields.get("Signer", "")
    ib, pb, idir = _base(img), _base(par), _dir(img)
    bad, good = {}, {}

    # --- lineage
    if pb in OFFICE and ib in SHELLS:
        bad["office_spawns_shell"] = f"{pb} -> {ib}"
    elif pb in BROWSERS and ib in SHELLS:
        bad["browser_spawns_shell"] = f"{pb} -> {ib}"
    elif pb in SERVICE_HOSTS and ib and ib not in EXPECTED.get(pb, ()):
        bad["service_host_spawns_proc"] = f"{pb} -> {ib}"
    elif pb and ib and ib in EXPECTED.get(pb, ()):
        good["expected_parent"] = f"{pb} -> {ib}"

    # --- identity
    ul = user.lower()
    if "system" in ul and "localsystem" not in ul:
        bad["system_context_exec"] = user
    elif "local service" in ul or "network service" in ul:
        good["restricted_service_acct"] = user
    if re.search(r"(?i)\\(guest|anonymous)$", user) or \
            str(fields.get("AuthPackage", "")).lower() == "ntlm" and \
            str(fields.get("LogonType", "")) == "3" and "guest" in ul:
        bad["blank_or_guest_account"] = user
    if str(fields.get("AuthPackage", "")).upper() in ("NTLM", "NTLMV1", "MSV1_0") \
            and eid in ("4624", "4625"):
        bad["legacy_auth_protocol"] = fields.get("AuthPackage", "")
    if str(fields.get("LogonType", "")) in ("0",) or \
            re.search(r"(?i)(sedebugprivilege|setcbprivilege|token.*eleva)", cmd):
        bad["privilege_escalation"] = _clip(cmd or fields.get("LogonType", ""))

    # --- image / path
    if eid in ("1", "4688"):
        if _in(idir, TEMP_DIRS):
            bad["temp_path_exec"] = img
        if ib in SYSTEM_NAMES and not _in(idir, SYSTEM_DIRS):
            bad["masquerading_name"] = img
        if ib in LOLBINS:
            bad["lolbin_exec"] = ib
    if signed == "false":
        bad["unsigned_binary"] = _base(tgt) or ib or "-"
    elif signed == "true" and signer:
        (good if "microsoft" in signer.lower() else good)[
            "signed_microsoft" if "microsoft" in signer.lower()
            else "signed_known_vendor"] = signer
    if idir and _in(idir, SYSTEM_DIRS):
        good["system32_path"] = idir

    # --- command line
    if cmd:
        if RE_ENCODED.search(cmd):
            bad["encoded_command"] = _clip(cmd)
        if RE_HIDDEN.search(cmd):
            bad["hidden_window"] = _clip(cmd, 80)
        if RE_CRADLE.search(cmd):
            bad["download_cradle"] = _clip(cmd)
        if RE_BYPASS.search(cmd):
            bad["exec_policy_bypass"] = _clip(cmd, 80)
        if RE_DISCOVERY.search(cmd):
            bad["discovery_command"] = _clip(cmd, 80)

    # --- file / registry
    if eid in ("11", "12", "13", "14"):
        t = (tgt or "").lower()
        if RE_AUTORUN.search(t):
            bad["service_binary_created" if "\\services\\" in t
                else "privilege_escalation" if "image file execution" in t
                else "masquerading_name"] = tgt
        if eid == "11" and (t.endswith(".exe") or t.endswith(".dll")) \
                and _in(t, TEMP_DIRS):
            bad["temp_path_exec"] = tgt
        if eid == "11" and "\\system32\\" in t and t.endswith(".exe"):
            bad["service_binary_created"] = tgt

    # --- network
    if eid == "3":
        port = str(fields.get("DestinationPort", ""))
        dip = str(fields.get("DestinationIp", ""))
        dns = fields.get("DestinationHostname", "")
        try:
            pn = int(port)
        except ValueError:
            pn = -1
        if RE_ADMIN_SHARE.search(cmd or "") or pn in (445, 139):
            bad["smb_admin_share"] = f"{dip}:{port}"
        if pn in (80, 443, 53, 123, 88, 389, 636, 3268):
            good["outbound_known_good"] = f"{dip}:{port}"
        elif pn >= 0 and pn not in (445, 139, 135, 3389, 5985, 5986):
            bad["outbound_uncommon_port"] = f"{dip}:{port}"
        if not dns and RE_IP.match(dip):
            bad["raw_ip_no_dns"] = dip
    if RE_ADMIN_SHARE.search(cmd or "") or re.search(r"(?i)\b(psexec|sc\s+\\\\|"
                                                     r"wmic\s+/node|winrs|"
                                                     r"invoke-command\s+-computername)", cmd or ""):
        bad["remote_service_install"] = _clip(cmd, 80)

    out = {}
    for k, v in list(bad.items()) + list(good.items()):
        if k in INDICATORS and k not in out:
            out[k] = _clip(v)
        if len(out) == 4:                        # OUTPUT_SCHEMA maxItems
            break
    if not out:
        out["expected_parent" if pb else "system32_path"] = \
            _clip(f"{pb} -> {ib}" if pb else (idir or img or "-")) or "-"
    return out

# ---------------------------------------------------------------- threatType

# first match wins; ordered by specificity, not severity
THREAT_RULES = [
    ("credential_stuffing", lambda f, i, c: str(f.get("EventID")) == "4625"),
    ("privilege_escalation", lambda f, i, c: "privilege_escalation" in i
     or "system_context_exec" in i and ("masquerading_name" in i or "temp_path_exec" in i)),
    ("lateral_movement", lambda f, i, c: "remote_service_install" in i
     or "smb_admin_share" in i),
    ("data_exfiltration", lambda f, i, c: bool(re.search(
        r"(?i)(compress-archive|\brar\s+a\b|7z\s+a\b|invoke-webrequest[^|]*-method\s+post|"
        r"\bftp\b|uploadfile)", c))),
    ("reconnaissance", lambda f, i, c: "discovery_command" in i),
    ("malware", lambda f, i, c: "download_cradle" in i or "encoded_command" in i
     or "temp_path_exec" in i or "masquerading_name" in i
     or "office_spawns_shell" in i or "browser_spawns_shell" in i),
    ("cryptomining", lambda f, i, c: bool(re.search(
        r"(?i)(xmrig|stratum\+tcp|minerd|nicehash)", c))),
    ("ransomware", lambda f, i, c: bool(RE_ANTIFOREN.search(c))),
    # persistence has no slot of its own in HIRA's threatType vocabulary; the
    # closest honest label for "something arranged to run again later" is
    # malware. Same for LOLBin abuse and unsigned code loading into a process.
    ("malware", lambda f, i, c: str(f.get("EventID")) in ("11", "12", "13", "14")
     and bool(RE_AUTORUN.search(c))),
    ("malware", lambda f, i, c: "lolbin_exec" in i or "unsigned_binary" in i
     or "service_binary_created" in i or "service_host_spawns_proc" in i
     or "raw_ip_no_dns" in i or "outbound_uncommon_port" in i),
    ("unknown", lambda f, i, c: True),
]


def threat_type(fields, ind, gold):
    if gold == "benign":
        return None
    cmd = " ".join(x for x in (fields.get("CommandLine", ""),
                               fields.get("TargetFilename", ""),
                               fields.get("TargetObject", ""),
                               fields.get("Details", "")) if x)
    for name, test in THREAT_RULES:
        try:
            if test(fields, ind, cmd):
                return name
        except Exception:
            continue
    return "unknown"

# ---------------------------------------------------------------- reasoning

BENIGN_KEYS = {"signed_microsoft", "signed_known_vendor", "system32_path",
               "expected_parent", "restricted_service_acct", "outbound_known_good"}

PHRASE = {
    "office_spawns_shell": "an Office application spawned a shell",
    "browser_spawns_shell": "a browser spawned a shell",
    "service_host_spawns_proc": "a service host spawned an unexpected child",
    "system_context_exec": "it runs in SYSTEM context",
    "lolbin_exec": "the image is a living-off-the-land binary",
    "temp_path_exec": "the image runs from a user-writable path",
    "unsigned_binary": "the binary is unsigned",
    "signature_invalid": "the signature failed validation",
    "masquerading_name": "the filename mimics a system binary outside a system path",
    "service_binary_created": "a service or system binary was written to disk",
    "hidden_window": "the window is hidden",
    "encoded_command": "the command line is encoded",
    "download_cradle": "the command line fetches remote content",
    "exec_policy_bypass": "execution policy is bypassed",
    "discovery_command": "it enumerates hosts, users or domains",
    "outbound_uncommon_port": "the destination port is non-standard",
    "outbound_known_good": "the destination is a well-known service on its usual port",
    "raw_ip_no_dns": "it connects to a literal IP with no DNS resolution",
    "remote_service_install": "it acts against a remote host",
    "smb_admin_share": "it touches an SMB administrative share",
    "blank_or_guest_account": "the account is guest or blank-password",
    "legacy_auth_protocol": "authentication is downgraded",
    "privilege_escalation": "privileges are being elevated",
    "signed_microsoft": "the binary carries a valid Microsoft signature",
    "signed_known_vendor": "the binary is signed by a known vendor",
    "system32_path": "it executes from a system path",
    "expected_parent": "the parent-child relationship is normal",
    "restricted_service_acct": "it runs under a restricted service account",
}

VERDICT = {
    "malicious": "This matches a known attack technique and should be treated as malicious.",
    "suspicious": "This is consistent with legitimate administration but also with an "
                  "attack in progress, so it warrants review rather than a verdict.",
    "benign": "Nothing here departs from normal activity for this host.",
}
ACTION = {
    "EventID: 1": "Process creation", "EventID: 4688": "Process creation",
    "EventID: 3": "Network connection", "EventID: 7": "Image load",
    "EventID: 11": "File creation", "EventID: 12": "Registry key operation",
    "EventID: 13": "Registry value set", "EventID: 4624": "Successful logon",
    "EventID: 4625": "Failed logon",
}


def reasoning(fields, ind, gold):
    head = ACTION.get(f"EventID: {fields.get('EventID','')}", "Event")
    img = _base(fields.get("Image", "")) or _base(fields.get("TargetFilename", "")) or "the subject"
    incrim = [PHRASE[k] for k in ind if k not in BENIGN_KEYS and k in PHRASE]
    excul = [PHRASE[k] for k in ind if k in BENIGN_KEYS and k in PHRASE]
    obs = incrim or excul
    if len(obs) > 2:
        obs = obs[:2]
    joined = obs[0] if len(obs) == 1 else " and ".join(obs) if obs else "no notable properties"
    if incrim and excul and gold != "benign":
        tail = f" The mitigating evidence ({excul[0]}) does not outweigh it."
    elif incrim and gold == "benign":
        tail = f" {excul[0].capitalize()}, which accounts for it." if excul else \
               " The pattern is documented normal behaviour for this binary."
    else:
        tail = ""
    return f"{head} by {img}: {joined}. {VERDICT[gold]}{tail}"

# ---------------------------------------------------------------- assembly


def build(row):
    fields = parse(row["event"])
    ind = extract(fields)
    gold = row["gold"]
    return {
        "severity": row["severity"],
        "isThreat": gold != "benign",
        "threatType": threat_type(fields, ind, gold),
        "indicators": ind,
        "reasoning": reasoning(fields, ind, gold),
    }


if __name__ == "__main__":
    import json, sys, collections
    rows = [json.loads(l) for l in open(sys.argv[1] if len(sys.argv) > 1
                                        else "train_final.jsonl")]
    ik, tt = collections.Counter(), collections.Counter()
    for r in rows:
        t = build(r)
        ik.update(t["indicators"].keys())
        tt[t["threatType"]] += 1
    print(f"{len(rows)} rows\n\nindicator frequency:")
    for k, v in ik.most_common():
        print(f"  {v:5} {v/len(rows):6.1%}  {k}")
    print(f"\nunused: {sorted(set(INDICATORS) - set(ik))}")
    print(f"\nthreatType: {dict(tt)}")
    for r in rows[:3]:
        print("\n" + "-" * 70 + f"\n{r['event']}\n->\n"
              + json.dumps(build(r), indent=2))
