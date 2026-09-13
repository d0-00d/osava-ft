# Attack candidate labels — paste into build_eval.py LABELS after culling
#
# KEEP/CUT rationale:
#   KEEP  = signal lives in command line, lineage, or context -> generalizes
#   CUT   = signal is the tool's filename -> model learns a lookup table that
#           any attacker defeats by renaming the binary
#
# severity -> gold bucket:  none/low -> benign, medium -> suspicious,
#                           high/critical -> malicious

ATTACK_LABELS = {
    # ---- KEEP: behavioural signal, no filename giveaway -------------------
    "A007": ("wermgr spawned by rundll32 temp DLL", "malicious", "high",
             "T1218.011 — rundll32 loading c:\\temp DLL via DllRegisterServer"),
    "A047": ("IIS worker spawns encoded PowerShell", "malicious", "critical",
             "T1505.003 webshell — w3wp.exe as parent is the whole signal"),
    "A064": ("comsvcs MiniDump LSASS", "malicious", "critical",
             "T1003.001 — signed LOLBin, System32 path, WmiPrvSE parent"),
    "A143": ("CHM spawns cmd, pastebin fetch", "malicious", "critical",
             "T1218.001 — hh.exe parent, remote script fetch"),
    "A152": ("cmd to rundll32 mshta remote", "malicious", "high",
             "T1218.005 — remote mshta payload"),
    "A165": ("regsvr32 remote SCT (Squiblydoo)", "malicious", "high",
             "T1218.010 — svchost parent is anomalous"),
    "A179": ("WMIC remote XSL (Squiblytwo)", "malicious", "high",
             "T1220 — signed binary, System32 path, remote XSL"),
    "A188": ("wscript runs .ico as VBS", "malicious", "critical",
             "T1059.005 — extension mismatch + nested encoding"),
    "A197": ("control.exe runs .cpl from Downloads", "malicious", "high",
             "T1218.002 — malicious CPL, invoice lure filename"),
    "A247": ("services.exe spawns hidden PowerShell", "malicious", "critical",
             "T1543.003 — service persistence, SYSTEM, gzip+base64"),
    "A280": ("PsExec service binary", "malicious", "high",
             "T1021.002 — THE case. Signed MS, C:\\Windows, services.exe parent. "
             "Matches synthetic E08."),
    "A306": ("PSEXESVC service registry", "malicious", "high",
             "T1021.002 corroborating event for A280"),
    "A330": ("WMI CommandLineEventConsumer", "malicious", "high",
             "T1546.003 — signed WMIC, persistence via subscription"),
    "A378": ("schtasks SilentCleanup /i", "malicious", "high",
             "T1548.002 UAC bypass — signed schtasks; parent name leaks, "
             "consider blanking UACME.exe to 'C:\\Users\\IEUser\\Desktop\\a.exe'"),
    "A473": ("schtasks /create from temp XML", "malicious", "high",
             "T1053.005 — temp-path task definition"),

    # ---- CUT or rename: filename is the only signal -----------------------
    "A050": ("PPLdump lsass", "malicious", "critical", "CUT — filename giveaway"),
    "A061": ("Outflank-Dumpert rundll32", "malicious", "critical",
             "CUT or rename DLL — tool name in argument"),
    "A075": ("ppldump lsass", "malicious", "critical", "CUT — duplicate of A050"),
    "A340": ("EfsPotato from temp", "malicious", "critical",
             "RENAME — keep the NETWORK SERVICE context, blank the filename"),
    "A348": ("NetworkServiceExploit", "malicious", "critical", "CUT — filename giveaway"),
    "A351": ("RogueWinRM", "malicious", "critical", "CUT — filename giveaway"),
    "A428": ("RoguePotato + nc64 reverse shell", "malicious", "critical",
             "RENAME — the -e cmd.exe reverse shell arg is real signal"),
    "A437": ("SpoolFool -dll", "malicious", "critical", "CUT — filename giveaway"),
    "A496": ("psexecprivesc from Public", "malicious", "high",
             "RENAME — C:\\Users\\Public path is the real signal"),
    "A157": ("rundll32 ieframe OpenURL", "malicious", "high",
             "CUT — python winpwnage.py parent is lab noise, never seen in prod"),
}

# Anything with a Python/winpwnage parent (A157, A330, A473) carries lab
# scaffolding that will not appear in production telemetry. If you keep them,
# rewrite ParentImage to something plausible (cmd.exe, powershell.exe).

KEEP = ["A007", "A047", "A064", "A143", "A152", "A165", "A179", "A188",
        "A197", "A247", "A280", "A306", "A330", "A378", "A473"]

RENAME = {  # path -> replacement, to strip tool-name shortcuts
    "A340": "C:\\Windows\\Temp\\svc32.exe",
    "A428": "C:\\Users\\IEUser\\AppData\\Local\\Temp\\upd.exe",
    "A496": "C:\\Users\\Public\\mspaint32.exe",
    "A061": "dbghelp_ext.dll",
}
