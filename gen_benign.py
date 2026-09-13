"""
Benign class generator (gold = benign, severity none/low).

Mitigates the PRD's "synthetic-only benign class" risk as far as synthesis
can: identities are drawn from the same pool as the attack corpus, the
EventID mix matches the measured attack mix, and roughly a third of the set
is deliberately *hard* -- signed vendor binaries executing out of AppData,
LOLBins used by their legitimate callers, outbound connections on
non-standard ports. A benign class made only of notepad.exe teaches the model
to reject everything that isn't notepad.

    python3 gen_benign.py --n 40 --out benign_events --sig backfill

Provenance per R13 goes to manifest.tsv: family, rationale, severity.
"""

import argparse
import json
from pathlib import Path

from contract import (DOMAIN, HOSTS, LOCAL_USERS, SERVERS, eid_target_counts,
                      home_of, pick_account, pick_parent, render, stable_rng,
                      validate)

SYS32 = "C:\\Windows\\System32"


def _u(r):
    """Account drawn from the shared cross-class distribution -- domain
    accounts must appear on both sides or the realm name becomes the label."""
    user = pick_account(r, r.choice(["local", "local", "domain"]))
    return user.split(chr(92))[0], user


def _user_home(user):
    return f"C:\\Users\\{user.split(chr(92))[-1]}"


# --------------------------------------------------------------------------
# EventID 1 -- Process Create
# --------------------------------------------------------------------------
def b_shell_ui(r):
    host, user = _u(r)
    home = _user_home(user)
    app, arg = r.choice([
        ("notepad.exe", f"{home}\\Documents\\notes.txt"),
        ("mspaint.exe", f"{home}\\Pictures\\screenshot.png"),
        ("calc.exe", ""),
        ("mmc.exe", "compmgmt.msc"),
    ])
    cmd = f'"{SYS32}\\{app}"' + (f" {arg}" if arg else "")
    par = pick_parent(r, groups=("interactive",))
    return dict(EventID=1, Image=f"{SYS32}\\{app}", CommandLine=cmd,
                ParentImage=par[0], ParentCommandLine=par[1], User=user), \
        ("desktop app launched from shell", None,
         "signed system binary, explorer parent, no arguments of interest")


def b_svchost(r):
    svc, acct = r.choice([
        ("LocalServiceNetworkRestricted", "NT AUTHORITY\\LOCAL SERVICE"),
        ("netsvcs", "NT AUTHORITY\\SYSTEM"),
        ("NetworkService", "NT AUTHORITY\\NETWORK SERVICE"),
        ("DcomLaunch", "NT AUTHORITY\\SYSTEM"),
        ("LocalSystemNetworkRestricted", "NT AUTHORITY\\SYSTEM"),
    ])
    return dict(EventID=1, Image=f"{SYS32}\\svchost.exe",
                CommandLine=f"C:\\Windows\\system32\\svchost.exe -k {svc} -p",
                ParentImage=f"{SYS32}\\services.exe",
                ParentCommandLine="C:\\Windows\\system32\\services.exe",
                User=acct), \
        ("service host startup", None,
         "services.exe parent is expected for svchost; -k group is a real one")


def b_vendor_updater_appdata(r):
    """HARD: signed vendor binary executing from AppData. Shares the temp-path
    surface with the malicious class; only the signature and lineage differ."""
    host, user = _u(r)
    home = _user_home(user)
    img, parent, cmd = r.choice([
        (f"{home}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
         f"{SYS32}\\svchost.exe", "/background"),
        (f"{home}\\AppData\\Local\\slack\\app-4.35.126\\slack.exe",
         "C:\\Windows\\explorer.exe", ""),
        (f"{home}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
         "C:\\Windows\\explorer.exe", ""),
        (f"{home}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
         f"{home}\\AppData\\Local\\Microsoft\\Teams\\Update.exe", "--processStart Teams.exe"),
    ])
    base = img.rsplit("\\", 1)[-1]
    pcmd = ("C:\\Windows\\system32\\svchost.exe -k UnistackSvcGroup"
            if parent.endswith("svchost.exe") else
            "C:\\Windows\\Explorer.EXE" if parent.endswith("explorer.exe") else parent)
    f = dict(EventID=1, Image=img, CommandLine=f'"{img}"' + (f" {cmd}" if cmd else ""),
             ParentImage=parent, ParentCommandLine=pcmd, User=user)
    return f, (f"{base} from AppData", None,
               "HARD NEGATIVE: user-writable path execution, but validly signed "
               "vendor binary with its own updater or explorer as parent")


def b_dev_toolchain(r):
    host, user = _u(r)
    home = _user_home(user)
    code = f"{home}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"
    img, cmd = r.choice([
        (f"{SYS32}\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"& {Import-Module "
         "PSReadLine}\""),
        ("C:\\Program Files\\nodejs\\node.exe",
         f'"C:\\Program Files\\nodejs\\node.exe" {home}\\src\\app\\build.js'),
        ("C:\\Program Files\\Git\\cmd\\git.exe", "git.exe status --porcelain"),
    ])
    f = dict(EventID=1, Image=img, CommandLine=cmd, ParentImage=code,
             ParentCommandLine=f'"{code}" --type=terminal', User=user)
    return f, ("developer toolchain in editor terminal", None,
               "HARD NEGATIVE: ExecutionPolicy Bypass appears here legitimately; "
               "the editor parent and profile-free module import are the exculpatory "
               "context")


def b_office(r):
    host, user = _u(r)
    home = _user_home(user)
    app = r.choice(["WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE"])
    doc = {"WINWORD.EXE": "Q3-report.docx", "EXCEL.EXE": "budget.xlsx",
           "OUTLOOK.EXE": None}[app]
    p = f"C:\\Program Files\\Microsoft Office\\root\\Office16\\{app}"
    cmd = f'"{p}"' + (f' "{home}\\Documents\\{doc}"' if doc else " /recycle")
    par = pick_parent(r, groups=("interactive",))
    return dict(EventID=1, Image=p, CommandLine=cmd,
                ParentImage=par[0], ParentCommandLine=par[1], User=user), \
        ("Office application launch", None,
         "Office as a leaf process, not as a parent of an interpreter")


def b_legit_lolbin(r):
    """HARD: rundll32 / msiexec / regsvr32 doing what they are actually for."""
    host, user = _u(r)
    img, cmd, parent, pcmd, why = r.choice([
        (f"{SYS32}\\rundll32.exe",
         f'"{SYS32}\\rundll32.exe" shell32.dll,Control_RunDLL "{SYS32}\\main.cpl",,1',
         f"{SYS32}\\control.exe", f'"{SYS32}\\control.exe" mouse',
         "rundll32 invoking a System32 CPL via control.exe -- same surface as "
         "A197, benign because the CPL is a signed system one, not a download"),
        (f"{SYS32}\\msiexec.exe",
         '"C:\\Windows\\System32\\msiexec.exe" /i "C:\\ProgramData\\Package Cache\\'
         '{a1b2c3}\\vcredist_x64.msi" /qn',
         f"{SYS32}\\services.exe", "C:\\Windows\\system32\\services.exe",
         "msiexec installing a cached redistributable under the installer service"),
        (f"{SYS32}\\rundll32.exe",
         f'"{SYS32}\\rundll32.exe" C:\\Windows\\system32\\davclnt.dll,DavSetCookie',
         f"{SYS32}\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k LocalService",
         "WebDAV cookie helper, a normal svchost child"),
        (f"{SYS32}\\dllhost.exe", f'{SYS32}\\dllhost.exe /Processid:{{3EB3C877-1F16-487C-9050-104DBCD66683}}',
         f"{SYS32}\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k DcomLaunch",
         "COM surrogate under DcomLaunch"),
    ])
    return dict(EventID=1, Image=img, CommandLine=cmd, ParentImage=parent,
                ParentCommandLine=pcmd, User=user), \
        ("LOLBin in its legitimate role", None, "HARD NEGATIVE: " + why)


def b_admin_routine(r):
    """Sysadmin doing plainly-scoped local work. Read-only, local, no network."""
    host, user = _u(r)
    cmd, why = r.choice([
        ('powershell.exe -NoProfile -Command "Get-Service -Name Spooler"',
         "single named service query"),
        ('"C:\\Windows\\System32\\ipconfig.exe" /all', "local network config"),
        ('"C:\\Windows\\System32\\tasklist.exe"', "local process list"),
    ])
    img = (f"{SYS32}\\WindowsPowerShell\\v1.0\\powershell.exe"
           if cmd.startswith("powershell") else
           f"{SYS32}\\{cmd.split(chr(92))[-1].split('.exe')[0]}.exe")
    par = pick_parent(r)
    return dict(EventID=1, Image=img, CommandLine=cmd, ParentImage=par[0],
                ParentCommandLine=par[1], User=user), \
        ("local admin housekeeping", None,
         f"single-target read-only command ({why}); contrast with the enumeration "
         "sweeps in the suspicious class")


def b_security_stack(r):
    acct = "NT AUTHORITY\\SYSTEM"
    img, cmd = r.choice([
        ("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.23110.3\\MsMpEng.exe",
         '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.23110.3\\MsMpEng.exe"'),
        (f"{SYS32}\\MpDefenderCoreService.exe", f'"{SYS32}\\MpDefenderCoreService.exe"'),
        (f"{SYS32}\\SecurityHealthService.exe", f'"{SYS32}\\SecurityHealthService.exe"'),
    ])
    f = dict(EventID=1, Image=img, CommandLine=cmd, ParentImage=f"{SYS32}\\services.exe",
             ParentCommandLine="C:\\Windows\\system32\\services.exe", User=acct)
    if img.startswith("C:\\ProgramData"):
        f["Signed"], f["Signer"] = "true", "Microsoft Corporation"
    return f, ("security product service start", None,
               "HARD NEGATIVE: SYSTEM-context service binary from ProgramData -- "
               "the exact shape of T1543.003, benign because it is Defender's "
               "versioned platform directory")


def b_unsigned_legit(r):
    """HARD: unsigned binaries are not rare in a real estate. In-house tools,
    dev builds and small-vendor utilities routinely ship without Authenticode.
    Without these, `Signed: false` is a perfect malicious detector and the
    model will never look past it."""
    host, user = _u(r)
    home = home_of(user)
    img, cmd, parent_g, why = r.choice([
        ("C:\\ProgramData\\ICORP\\tools\\assetcheck.exe",
         '"C:\\ProgramData\\ICORP\\tools\\assetcheck.exe" --report',
         ("scheduled",), "in-house inventory agent, unsigned, run by the "
                         "logon script"),
        (f"{home}\\src\\build\\Debug\\app.exe",
         f'"{home}\\src\\build\\Debug\\app.exe" --test',
         ("interactive",), "developer running a local debug build"),
        # the attack corpus contains a tool compiled from source, so
        # "\\output\\x64\\Release\\" became a malicious-only path shape. Build
        # output directories are where developers' own binaries live.
        (f"{home}\\Source\\Repos\\svc\\output\\x64\\Release\\svc.exe",
         f'"{home}\\Source\\Repos\\svc\\output\\x64\\Release\\svc.exe" --selftest',
         ("interactive",), "freshly built binary run from its Release output directory"),
        (f"{home}\\Source\\Repos\\tools\\output\\x64\\Release\\gen.exe",
         f'"{home}\\Source\\Repos\\tools\\output\\x64\\Release\\gen.exe" --emit schema.json',
         ("scheduled",), "in-house code generator invoked by the build"),
        ("C:\\Program Files\\WinDirStat\\windirstat.exe",
         '"C:\\Program Files\\WinDirStat\\windirstat.exe"',
         ("interactive",), "small-vendor utility that ships unsigned"),
    ])
    par = pick_parent(r, groups=parent_g)
    f = dict(EventID=1, Image=img, CommandLine=cmd, ParentImage=par[0],
             ParentCommandLine=par[1], User=user, Signed="false")
    return f, ("unsigned but legitimate binary", None, "HARD NEGATIVE: " + why)


def b_payload_proof_binaries(r):
    """Red teams spawn calc.exe, osk.exe and notepad.exe to prove code
    execution without doing damage, so the attack corpus contains them almost
    exclusively as the child of regsvr32 / mshta / rundll32. Left alone the
    model learns "calc.exe = malicious", which in production means flagging a
    user opening Calculator. These are the same binaries launched the ordinary
    way; the lineage is what carries the signal, not the name."""
    host, user = _u(r)
    app = r.choice(["calc.exe", "osk.exe", "notepad.exe", "charmap.exe",
                    "magnify.exe", "mspaint.exe", "write.exe"])
    par = pick_parent(r, groups=("interactive",))
    return dict(EventID=1, Image=f"{SYS32}\\{app}",
                CommandLine=f'"{SYS32}\\{app}"',
                ParentImage=par[0], ParentCommandLine=par[1], User=user), \
        (f"{app} launched normally", None,
         "HARD NEGATIVE: a binary the attack corpus only ever shows as a "
         "red-team payload proof, here launched the way a person launches it")


def b_long_cmdline(r):
    """R3 truncates at 512 characters with an explicit marker. Only attack
    command lines were long enough to hit it, so `<truncated>` became a
    perfect malicious predictor -- an artifact of our own contract, not of the
    data. Real build, installer and Java command lines are enormous; these
    exist so the marker appears on both sides of the label."""
    host, user = _u(r)
    home = home_of(user)
    kind = r.choice(["msbuild", "java", "installer", "cl"])
    if kind == "msbuild":
        img = ("C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community"
               "\\MSBuild\\Current\\Bin\\MSBuild.exe")
        cmd = (f'"{img}" /nologo /nodemode:1 /nodeReuse:true /low:false '
               f'/p:Configuration=Release /p:Platform=x64 /p:OutDir='
               f'{home}\\source\\repos\\svc\\bin\\Release\\ /p:VisualStudioVersion=16.0 '
               f'/p:SolutionDir={home}\\source\\repos\\svc\\ /t:Rebuild /m:8 /v:minimal '
               f'/flp:LogFile={home}\\source\\repos\\svc\\msbuild.log;Verbosity=diagnostic '
               f'/p:DefineConstants="TRACE;RELEASE;NETSTANDARD2_0" '
               f'{home}\\source\\repos\\svc\\svc.sln')
        parent = ("C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community"
                  "\\Common7\\IDE\\devenv.exe")
        pcmd = f'"{parent}" {home}\\source\\repos\\svc\\svc.sln'
        why = "release build invoked from the IDE"
    elif kind == "java":
        img = "C:\\Program Files\\Eclipse Adoptium\\jdk-17\\bin\\java.exe"
        cp = ";".join(f"{home}\\.m2\\repository\\org\\example\\lib{i}\\1.{i}.0\\lib{i}-1.{i}.0.jar"
                      for i in range(9))
        cmd = (f'"{img}" -Xms512m -Xmx4096m -XX:+UseG1GC -Dfile.encoding=UTF-8 '
               f'-Djava.net.preferIPv4Stack=true -classpath "{cp}" com.example.svc.Main '
               f'--spring.profiles.active=prod')
        parent = "C:\\Windows\\System32\\services.exe"
        pcmd = "C:\\Windows\\system32\\services.exe"
        why = "JVM service start with a full dependency classpath"
    elif kind == "installer":
        img = f"{SYS32}\\msiexec.exe"
        cmd = (f'"{img}" /i "C:\\ProgramData\\Package Cache\\'
               f'{{9a2b1c3d-4e5f-6789-abcd-ef0123456789}}\\vcredist_x64.msi" /qn /norestart '
               f'/L*v "C:\\Windows\\Temp\\vcredist_x64_install.log" '
               f'ALLUSERS=1 REBOOT=ReallySuppress ARPSYSTEMCOMPONENT=1 '
               f'MSIFASTINSTALL=7 TRANSFORMS=":1033;:InstallShield" '
               f'INSTALLDIR="C:\\Program Files\\Common Files\\Microsoft Shared\\VC" '
               f'SETUPEXEDIR="C:\\ProgramData\\Package Cache" '
               f'EXTUI=1 DISABLEADVTSHORTCUTS=1 SKIPVSUPDATE=1')
        parent = f"{SYS32}\\services.exe"
        pcmd = "C:\\Windows\\system32\\services.exe"
        why = "redistributable installed silently with full verbose logging"
    else:
        img = ("C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community"
               "\\VC\\Tools\\MSVC\\14.26.28801\\bin\\Hostx64\\x64\\cl.exe")
        inc = " ".join(f'/I"{home}\\source\\repos\\svc\\include\\mod{i}"' for i in range(8))
        cmd = (f'"{img}" /c /nologo /W3 /WX- /diagnostics:column /O2 /Oi /GL /D NDEBUG '
               f'/D _CONSOLE /D _UNICODE /D UNICODE {inc} /Gm- /EHsc /MD /GS /Gy '
               f'/fp:precise /permissive- /Zc:wchar_t /Zc:forScope /Zc:inline '
               f'/std:c++17 /Fo"x64\\Release\\" /Fd"x64\\Release\\vc142.pdb" '
               f'/external:W3 /Gd /TP /FC main.cpp')
        parent = ("C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community"
                  "\\MSBuild\\Current\\Bin\\Tracker.exe")
        pcmd = f'"{parent}" /c cl.exe'
        why = "C++ compiler invocation with a full flag set"
    return dict(EventID=1, Image=img, CommandLine=cmd, ParentImage=parent,
                ParentCommandLine=pcmd, User=user), \
        ("long build/install command line", None,
         "HARD NEGATIVE: exceeds the 512-char contract cap, so the truncation "
         "marker appears on a benign event -- " + why)


def b_iis_normal(r):
    """The attack corpus contains exactly one IIS capture, a webshell, so
    `IIS APPPOOL\\DefaultAppPool` appears only in malicious events and the
    account name alone predicts the class. A web server has to be able to look
    normal. The real signal in the webshell case is the lineage -- w3wp.exe
    parenting a shell -- not the identity it runs as."""
    pool = r.choice(["DefaultAppPool", "IntranetPool", "ApiPool"])
    acct = f"IIS APPPOOL\\{pool}"
    w3wp = "C:\\Windows\\System32\\inetsrv\\w3wp.exe"
    pcmd = (f'c:\\windows\\system32\\inetsrv\\w3wp.exe -ap "{pool}" '
            f'-v "v4.0" -l "webengine4.dll" -a \\\\.\\pipe\\iisipm{r.randrange(10**8):08x}')
    kind = r.choice(["worker", "recycle", "net", "file"])
    if kind == "worker":
        f = dict(EventID=1, Image=w3wp, CommandLine=pcmd,
                 ParentImage="C:\\Windows\\System32\\svchost.exe",
                 ParentCommandLine="C:\\Windows\\system32\\svchost.exe -k iissvcs",
                 User=acct)
        why = "application pool worker started by the WAS service -- the normal way w3wp appears"
    elif kind == "recycle":
        f = dict(EventID=1, Image="C:\\Windows\\System32\\inetsrv\\appcmd.exe",
                 CommandLine=f'"C:\\Windows\\System32\\inetsrv\\appcmd.exe" '
                             f'recycle apppool /apppool.name:"{pool}"',
                 ParentImage="C:\\Windows\\System32\\cmd.exe",
                 ParentCommandLine='"C:\\Windows\\System32\\cmd.exe"',
                 User=pick_account(r, "admin"))
        why = ("HARD NEGATIVE: appcmd is the same binary the webshell capture uses "
               "for credential discovery; recycling a pool is its ordinary job")
    elif kind == "net":
        f = dict(EventID=3, Image=w3wp, User=acct,
                 DestinationIp="10.14.7.33", DestinationPort=1433,
                 DestinationHostname="ICORP-APP03.icorp.local")
        why = "web tier reaching its database on the standard SQL port"
    else:
        f = dict(EventID=11, Image=w3wp,
                 TargetFilename="C:\\inetpub\\temp\\IIS Temporary Compressed "
                                "Files\\{}\\index.htm.gz".format(pool))
        why = "IIS writing its own compression cache"
    return f, ("normal IIS activity", None, why)


def b_logon_ui(r):
    host, user = _u(r)
    return dict(EventID=1, Image=f"{SYS32}\\userinit.exe",
                CommandLine=f"{SYS32}\\userinit.exe",
                ParentImage=f"{SYS32}\\winlogon.exe",
                ParentCommandLine="winlogon.exe", User=user), \
        ("interactive logon chain", None, "winlogon -> userinit is the standard chain")


# --------------------------------------------------------------------------
# EventID 3 -- Network Connection
# --------------------------------------------------------------------------
def b_net_https(r):
    host, user = _u(r)
    home = _user_home(user)
    img, dns, ip = r.choice([
        (f"{home}\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
         "www.google.com", "142.250.190.78"),
        (f"{home}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
         "graph.microsoft.com", "20.190.159.23"),
        (f"{SYS32}\\svchost.exe", "fe2.update.microsoft.com", "20.72.235.82"),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
         "outlook.office365.com", "52.96.104.34"),
    ])
    return dict(EventID=3, Image=img, User=user, DestinationIp=ip,
                DestinationPort=443, DestinationHostname=dns), \
        ("HTTPS to a named service", None,
         "standard port, resolved hostname, well-known destination")


def b_net_uncommon_port(r):
    """HARD: non-standard port with an exculpatory hostname."""
    host, user = _u(r)
    home = _user_home(user)
    img, dns, ip, port, why = r.choice([
        (f"{home}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
         "worldaz.tr.teams.microsoft.com", "52.113.194.132", 3478,
         "Teams media relay on STUN/TURN 3478"),
        (f"{SYS32}\\svchost.exe", "ntp.icorp.local", "10.14.2.11", 123,
         "domain time sync"),
        ("C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe",
         "ICORP-APP03.icorp.local", "10.14.7.33", 1433,
         "internal SQL client session"),
    ])
    return dict(EventID=3, Image=img, User=user, DestinationIp=ip,
                DestinationPort=port, DestinationHostname=dns), \
        ("non-standard port, known service", None, "HARD NEGATIVE: " + why)


# --------------------------------------------------------------------------
# EventID 7 -- Image Load
# --------------------------------------------------------------------------
def b_image_load(r):
    dll = r.choice(["crypt32.dll", "wintrust.dll", "amsi.dll", "combase.dll",
                    "winhttp.dll"])
    img = r.choice([f"{SYS32}\\svchost.exe", f"{SYS32}\\explorer.exe",
                    f"{SYS32}\\WindowsPowerShell\\v1.0\\powershell.exe"])
    return dict(EventID=7, Image=img, Signed="true", Signer="Microsoft Windows",
                TargetFilename=f"{SYS32}\\{dll}"), \
        (f"{dll} load", None, "signed system DLL loaded by a system binary")


# --------------------------------------------------------------------------
# EventID 11 -- File Create
# --------------------------------------------------------------------------
def b_file_create(r):
    host, user = _u(r)
    home = _user_home(user)
    img, tgt, why = r.choice([
        (f"{home}\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
         f"{home}\\Downloads\\quarterly-summary.pdf", "browser download of a document"),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
         f"{home}\\AppData\\Local\\Microsoft\\Office\\16.0\\OfficeFileCache\\ftmp0001",
         "Office file cache write"),
        (f"{SYS32}\\svchost.exe",
         "C:\\Windows\\SoftwareDistribution\\Download\\a1f4\\update.cab",
         "Windows Update payload staging"),
        (f"{home}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
         f"{home}\\AppData\\Roaming\\Code\\logs\\20260907\\renderer.log",
         "editor log write"),
        (f"{SYS32}\\msiexec.exe", "C:\\Windows\\Temp\\MSI4a2f1.LOG",
         "HARD NEGATIVE: installer writing to Windows\\Temp -- Temp is where "
         "Windows itself works, not a malicious-only path"),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
         f"{home}\\AppData\\Local\\Temp\\~$budget.xlsx",
         "Office lock file in the user Temp directory"),
    ])
    return dict(EventID=11, Image=img, TargetFilename=tgt), \
        ("routine file write", None, why)


# --------------------------------------------------------------------------
# EventID 12 / 13 -- Registry
# --------------------------------------------------------------------------
def b_registry(r):
    eid, img, tgt, why = r.choice([
        (13, f"{SYS32}\\svchost.exe",
         "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\LastScanTime",
         "update agent bookkeeping"),
        (13, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
         "HKCU\\Software\\Google\\Chrome\\PreferenceMACs\\Default\\pinned_tabs",
         "browser preference write"),
        (12, f"{SYS32}\\services.exe",
         "HKLM\\System\\CurrentControlSet\\Services\\WinDefend\\Start",
         "HARD NEGATIVE: service registry key under Services -- structurally "
         "identical to A306 (PSEXESVC), benign because the service is Defender"),
        (13, f"{SYS32}\\msiexec.exe",
         "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{a1b2c3}\\DisplayName",
         "installer registering an uninstall entry"),
        (13, "C:\\Program Files\\NVIDIA Corporation\\Display.NvContainer\\NVDisplay.Container.exe",
         "HKLM\\SOFTWARE\\NVIDIA Corporation\\Global\\NvContainer\\LastRun",
         "vendor service bookkeeping"),
    ])
    return dict(EventID=eid, Image=img, TargetFilename=tgt), \
        ("registry write", None, why)


# --------------------------------------------------------------------------
# EventID 4624 -- Logon
# --------------------------------------------------------------------------
def b_logon(r):
    host, user = _u(r)
    lt, pkg, ip, why = r.choice([
        (2, "Negotiate", None, "interactive console logon"),
        (7, "Negotiate", None, "workstation unlock"),
        (5, "Negotiate", None, "service logon"),
        (3, "Kerberos", "10.14.2.11", "network logon from a domain controller, Kerberos"),
        (11, "Negotiate", None, "cached interactive logon, laptop off-network"),
    ])
    f = dict(EventID=4624, User=user if lt != 5 else "NT AUTHORITY\\SYSTEM",
             LogonType=lt, AuthPackage=pkg)
    if ip:
        f["DestinationIp"] = ip
    return f, ("standard logon", None, why)


FAMILIES = {
    1: [b_shell_ui, b_svchost, b_vendor_updater_appdata, b_dev_toolchain, b_office,
        b_legit_lolbin, b_admin_routine, b_security_stack, b_logon_ui,
        b_unsigned_legit, b_iis_normal, b_long_cmdline,
        b_payload_proof_binaries, b_payload_proof_binaries,
        b_payload_proof_binaries],
    3: [b_net_https, b_net_uncommon_port],
    7: [b_image_load],
    11: [b_file_create],
    12: [b_registry],
    13: [b_registry],
    4624: [b_logon],
    4625: [b_logon],
}

# severity within the benign bucket: `low` for the hard negatives that a
# reasonable analyst would glance at twice, `none` for the rest.
LOW_FAMILIES = {"b_vendor_updater_appdata", "b_dev_toolchain", "b_legit_lolbin",
                "b_net_uncommon_port", "b_security_stack", "b_unsigned_legit",
                "b_iis_normal", "b_long_cmdline"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--out", default="benign_events")
    ap.add_argument("--prefix", default="B")
    ap.add_argument("--sig", choices=["backfill", "strip"], default="backfill")
    ap.add_argument("--seed", default="osava-benign-v1")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob(f"{args.prefix}*.txt"):
        old.unlink()

    targets = eid_target_counts(args.n)
    rows, bodies, n = [], set(), 0
    labels = {}

    for eid, want in sorted(targets.items()):
        fams = FAMILIES.get(eid, [])
        if not fams or want == 0:
            continue
        got, tries = 0, 0
        while got < want and tries < want * 40:
            tries += 1
            fn = fams[tries % len(fams)]
            r = stable_rng(f"{args.seed}|{eid}|{fn.__name__}|{tries}")
            fields, (name, attck, why) = fn(r)
            fields["EventID"] = eid if eid in (12, 13, 4624, 4625) else fields["EventID"]
            body = render(fields, sig_mode=args.sig)
            if body in bodies:
                continue
            errs = validate(body)
            if errs:
                raise SystemExit(f"{fn.__name__}: {errs}")
            bodies.add(body)
            n += 1
            got += 1
            eid_ = f"{args.prefix}{n:03d}"
            (out / f"{eid_}.txt").write_text(body + "\n")
            sev = "low" if fn.__name__ in LOW_FAMILIES else "none"
            labels[eid_] = (name, "benign", sev, why)
            rows.append("\t".join([eid_, "synthetic:gen_benign.py", str(eid),
                                   fn.__name__, sev, attck or "-", why]))

    (out / "manifest.tsv").write_text(
        "file\tsource\tevent_id\tfamily\tseverity\tattck\trationale\n"
        + "\n".join(rows) + "\n")
    (out / "labels.json").write_text(json.dumps(labels, indent=2))
    print(f"wrote {n} benign events to {out}/  (sig={args.sig})")
    print("eid mix:", {k: v for k, v in sorted(targets.items()) if v})
    sev = {}
    for _, _, s, _ in labels.values():
        sev[s] = sev.get(s, 0) + 1
    print("severity:", sev)


if __name__ == "__main__":
    main()
