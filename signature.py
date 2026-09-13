"""
Behaviour signatures: collapse an event to what it *does*, discarding who did
it and where.

Two consumers, one definition:

  build_profile.py  turns the real Sysmon capture into a set of signatures that
                    are known-ambient on a working machine
  prefilter.py      asks, of each attack-corpus event, whether its signature is
                    ambient -- which is how the A002 / A027 problem gets solved
                    mechanically instead of by reading 1500 events

The normalisation is deliberately aggressive. Usernames, profile paths, GUIDs,
version directories, PIDs, random filenames, base64 payloads and IP addresses
all collapse to placeholders. Two events share a signature when they are the
same behaviour performed by different people on different days -- which is
exactly the equivalence class we want to count.
"""

import re

# order matters: most specific first
SUBS = [
    (re.compile(r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-"
                r"[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"), "<GUID>"),
    (re.compile(r"S-1-5-21-[\d-]+"), "<SID>"),
    (re.compile(r"(?i)\b[a-z]:\\users\\[^\\\s\"]+"), "<PROFILE>"),
    (re.compile(r"(?i)\\(users|documents and settings)\\[^\\\s\"]+"), r"\\<PROFILE>"),
    (re.compile(r"\b\d+\.\d+\.\d+(\.\d+)?\b(?!\.\d)"), "<VER>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
    # long opaque blobs: base64 payloads, hashes, random names
    (re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"), "<B64>"),
    (re.compile(r"\b[a-fA-F0-9]{16,}\b"), "<HEX>"),
    (re.compile(r"(?i)\b[a-z0-9]{8}\.(tmp|dat|log|bin)\b"), "<RANDFILE>"),
    (re.compile(r"(?i)\\pipe\\[^\s\"]+"), r"\\pipe\\<PIPE>"),
    (re.compile(r"\b\d{3,}\b"), "<N>"),
]

# a version directory such as \4.18.23110.3\ or \app-4.35.126\
VERDIR = re.compile(r"(?i)\\(?:app-)?<VER>\\")


def normalise(s):
    if not s:
        return ""
    s = s.replace("%%", "%")
    for pat, rep in SUBS:
        s = pat.sub(rep, s)
    s = VERDIR.sub(r"\\<VERDIR>\\", s)
    return " ".join(s.lower().split())


def basename(path):
    if not path:
        return ""
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def dirname(path):
    if not path:
        return ""
    p = path.replace("/", "\\")
    return normalise(p.rsplit("\\", 1)[0]).lower() if "\\" in p else ""


# command-line arguments carry the technique; the image path carries the
# identity. Keep the argument shape, drop the leading image repetition.
def cmd_shape(cmdline, image):
    c = normalise(cmdline)
    b = basename(image)
    if b:
        # strip the (possibly quoted, possibly full-path) leading image token
        c = re.sub(r'^"?[^"\s]*' + re.escape(b) + r'"?\s*', "", c)
    return c[:300]


WELL_KNOWN = {80, 443, 53, 88, 123, 135, 139, 389, 445, 636, 3268, 3389,
              1433, 5985, 5986, 25, 110, 143, 993, 995}
SUSPECT_PORTS = {4444, 1337, 8080, 8443, 9001, 1234, 31337, 6666, 6667, 8888}


def port_bucket(p):
    try:
        n = int(p)
    except (TypeError, ValueError):
        return "noport"
    if n in SUSPECT_PORTS:
        return f"suspect:{n}"
    if n in WELL_KNOWN:
        return f"wk:{n}"
    if n >= 49152:
        return "ephemeral"
    if n < 1024:
        return "low"
    return "registered"


def signature(fields):
    """The equivalence class. Same tuple == same behaviour."""
    eid = str(fields.get("EventID", ""))
    img = fields.get("Image", "")
    par = fields.get("ParentImage", "")
    parts = [eid, basename(img), dirname(img), basename(par)]
    if eid in ("1", "4688"):
        parts.append(cmd_shape(fields.get("CommandLine", ""), img))
    elif eid in ("11", "12", "13"):
        parts.append(normalise(fields.get("TargetFilename", ""))[:200])
    elif eid == "3":
        # bucket the port. A client's ephemeral source-side port is different on
        # every connection, so keeping it literal makes every network event its
        # own signature and defeats the whole grouping -- which is how a plain
        # svchost connection scored as "unique to this capture".
        parts += [port_bucket(fields.get("DestinationPort")),
                  "dns" if fields.get("DestinationHostname") else "nodns"]
    elif eid in ("4624", "4625"):
        parts += [str(fields.get("LogonType", "")), str(fields.get("AuthPackage", ""))]
    elif eid == "7":
        parts.append(normalise(fields.get("TargetFilename", ""))[:200])
    return "|".join(parts)


def coarse_signature(fields):
    """Looser class: image and parent only, no arguments. Catches ambient
    activity whose arguments vary run to run (svchost -k groups, browser
    connections) without letting a payload hide behind a common parent."""
    eid = str(fields.get("EventID", ""))
    return "|".join([eid, basename(fields.get("Image", "")),
                     basename(fields.get("ParentImage", ""))])
