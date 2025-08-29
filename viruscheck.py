# Advanced heuristic virus scanner (Colab-friendly, educational)
# Notes:
# - Uses only Python stdlib
# - Scans files you upload; safely peeks into ZIPs (1 level deep)
# - Heuristic scoring is illustrative; tune for your needs

import io, os, re, json, math, time, hashlib, zipfile, mimetypes
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple
from google.colab import files
from IPython.display import clear_output

# ============== Configuration ==============
# Risk thresholds
THRESHOLDS = {
    "caution": 20,
    "suspicious": 40,
    "high": 60,
    "malicious": 80
}

# Rule weights
WEIGHTS = {
    "known_bad_hash": 100,
    "very_high_entropy": 20,
    "high_entropy": 12,
    "susp_string": 5,            # per hit, capped below
    "susp_string_cap": 30,
    "packer_upx": 15,
    "network_artifact": 10,
    "macro_container": 25,
    "base64_long": 10,
    "mismatch_ext_magic": 10,
    "script_executable": 10
}

# Known bad hashes (DEMO: placeholder values; replace with real, verified IOC hashes)
KNOWN_BAD_SHA256 = {
    # "aaaaaaaa...": "Example_Malware.Family",
}

# Extensions of concern
SUSPICIOUS_EXT = {
    ".exe",".scr",".js",".jse",".vbs",".vbe",".ps1",".psm1",".bat",".cmd",
    ".lnk",".dll",".jar",".elf",".apk",".py",".hta",".chm",".msi"
}

# Suspicious strings (ASCII). Keep generic and non-malware-distributing.
SUSPICIOUS_STRINGS = [
    # LOLBins / tooling
    "powershell", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
    "cmd.exe", "bitsadmin", "certutil", "schtasks", "wevtutil", "bcdedit",
    # Process & injection hints
    "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory", "OpenProcess",
    "NtUnmapViewOfSection", "GetProcAddress", "LoadLibrary",
    # Network / exfil
    "http://", "https://", "ftp://", "POST ", "GET ", "User-Agent",
    # Evasion / encoding
    "-enc", "base64", "FromBase64String", "xor", "AES", "RC4",
    # Download/exec patterns
    "curl ", "wget ", "Invoke-WebRequest", "Start-Process",
    # Reverse shell hints
    "bash -i", "/bin/sh", "nc ", "ncat ", "socat "
]

# Network artifacts (counted separately)
NETWORK_STRINGS = ["http://", "https://", "socket", "connect", "POST ", "GET "]

# Archive limits (bomb guard)
ZIP_MAX_FILES = 200
ZIP_MAX_TOTAL_UNCOMPRESSED = 200 * 1024 * 1024  # 200 MB
ZIP_MAX_RATIO = 100  # max allowed ratio uncompressed/compressed per file

# Quarantine suspect files inside Colab session
QUARANTINE = False
QUARANTINE_DIR = "./quarantine"


# ============== Utilities ==============

def sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def file_magic(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "PE"
    if data.startswith(b"%PDF-"):
        return "PDF"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP"
    if data.startswith(bytes.fromhex("D0CF11E0A1B11AE1")):
        return "OLE"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    return "UNKNOWN"

def guess_text(data: bytes) -> bool:
    # Heuristic: treat as text if most bytes printable/whitespace
    if not data:
        return False
    sample = data[:4096]
    printable = sum(32 <= b <= 126 or b in (9,10,13) for b in sample)
    return printable / len(sample) > 0.85

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    counts = Counter(data)
    n = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent

def extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    return re.findall(rb"[ -~]{%d,}" % min_len, data)

def has_long_base64(s: bytes, min_run: int = 40) -> bool:
    # Looks for long base64-like runs
    return re.search(rb"[A-Za-z0-9+/=]{%d,}" % min_run, s) is not None

def extension(path: str) -> str:
    return os.path.splitext(path)[1].lower()

def safe_zip_members(zf: zipfile.ZipFile) -> List[zipfile.ZipInfo]:
    infos = zf.infolist()
    if len(infos) > ZIP_MAX_FILES:
        return []
    total_uncompressed = sum(i.file_size for i in infos)
    if total_uncompressed > ZIP_MAX_TOTAL_UNCOMPRESSED:
        return []
    safe = []
    for zi in infos:
        comp = max(1, zi.compress_size)
        ratio = zi.file_size / comp
        if ratio > ZIP_MAX_RATIO:
            continue
        safe.append(zi)
    return safe

def verdict_from_score(score: int) -> str:
    if score >= THRESHOLDS["malicious"]:
        return "Malicious"
    if score >= THRESHOLDS["high"]:
        return "High Risk"
    if score >= THRESHOLDS["suspicious"]:
        return "Suspicious"
    if score >= THRESHOLDS["caution"]:
        return "Caution"
    return "Likely Clean"

@dataclass
class Finding:
    name: str
    weight: int
    detail: str

@dataclass
class ScanResult:
    filename: str
    size: int
    sha256: str
    filetype: str
    mimetype: Optional[str]
    entropy: float
    strings_hits: int
    network_hits: int
    base64_flag: bool
    macro_flag: bool
    upx_flag: bool
    ext_magic_mismatch: bool
    script_exec_ext: bool
    score: int
    verdict: str
    findings: List[Finding]
    nested: List[Any]  # nested results for archives


# ============== Core scanning ==============

def analyze_bytes(data: bytes, fname: str) -> ScanResult:
    ftype = file_magic(data)
    ent = shannon_entropy(data)
    sha = sha256(data)
    mime, _ = mimetypes.guess_type(fname)
    ext = extension(fname)

    # Known bad hash
    findings: List[Finding] = []
    score = 0
    if sha in KNOWN_BAD_SHA256:
        findings.append(Finding("Known bad hash", WEIGHTS["known_bad_hash"], KNOWN_BAD_SHA256[sha]))
        score += WEIGHTS["known_bad_hash"]

    # Strings and patterns
    strings = extract_ascii_strings(data, 4)
    joined = b"\n".join(strings)[:2_000_000]  # cap to avoid huge memory
    strings_text = joined.lower()

    # Suspicious strings
    susp_hits = sum(1 for s in SUSPICIOUS_STRINGS if s.encode() in strings_text)
    if susp_hits:
        add = min(WEIGHTS["susp_string_cap"], susp_hits * WEIGHTS["susp_string"])
        findings.append(Finding("Suspicious strings", add, f"{susp_hits} hits"))
        score += add

    # Network artifacts
    net_hits = sum(1 for s in NETWORK_STRINGS if s.encode() in strings_text)
    if net_hits:
        findings.append(Finding("Network artifacts", WEIGHTS["network_artifact"], f"{net_hits} hits"))
        score += WEIGHTS["network_artifact"]

    # UPX packer hint
    upx = b"UPX!" in data or b"UPX" in strings_text
    if upx:
        findings.append(Finding("Packer hint (UPX)", WEIGHTS["packer_upx"], "UPX signature found"))
        score += WEIGHTS["packer_upx"]

    # Entropy-based
    if ent >= 7.2:
        findings.append(Finding("Very high entropy", WEIGHTS["very_high_entropy"], f"H={ent:.2f}"))
        score += WEIGHTS["very_high_entropy"]
    elif ent >= 6.8:
        findings.append(Finding("High entropy", WEIGHTS["high_entropy"], f"H={ent:.2f}"))
        score += WEIGHTS["high_entropy"]

    # Macro/container hints
    macro = False
    if ftype == "ZIP":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = [zi.filename for zi in safe_zip_members(zf)]
                # Modern Office macro artifacts
                if any("vbaProject.bin" in n for n in names):
                    macro = True
        except zipfile.BadZipFile:
            pass
    elif ftype == "OLE":
        # Legacy Office container; cannot confirm macros without extra libs, so hint
        macro = True
    if macro:
        findings.append(Finding("Macro container", WEIGHTS["macro_container"], "Office macro artifact"))
        score += WEIGHTS["macro_container"]

    # Base64 long runs
    b64 = has_long_base64(joined)
    if b64:
        findings.append(Finding("Long base64 run", WEIGHTS["base64_long"], "Possible obfuscated payload"))
        score += WEIGHTS["base64_long"]

    # Extension vs magic mismatch
    mismatch = False
    if ext and ftype != "UNKNOWN":
        # Simple expectations
        expected_map = {
            ".exe": "PE", ".dll": "PE", ".pdf": "PDF", ".zip": "ZIP",
            ".docm": "ZIP", ".xlsm": "ZIP", ".pptm": "ZIP",
            ".doc": "OLE", ".xls": "OLE", ".ppt": "OLE",
            ".elf": "ELF", ".apk": "ZIP", ".jar": "ZIP"
        }
        expected = expected_map.get(ext)
        if expected and expected != ftype:
            mismatch = True
    if mismatch:
        findings.append(Finding("Extension/magic mismatch", WEIGHTS["mismatch_ext_magic"], f"{ext} vs {ftype}"))
        score += WEIGHTS["mismatch_ext_magic"]

    # Executable/script extension
    script_exec = ext in SUSPICIOUS_EXT
    if script_exec:
        findings.append(Finding("Executable/script extension", WEIGHTS["script_executable"], ext))
        score += WEIGHTS["script_executable"]

    verdict = verdict_from_score(score)

    return ScanResult(
        filename=fname,
        size=len(data),
        sha256=sha,
        filetype=ftype,
        mimetype=mime,
        entropy=ent,
        strings_hits=susp_hits,
        network_hits=net_hits,
        base64_flag=b64,
        macro_flag=macro,
        upx_flag=upx,
        ext_magic_mismatch=mismatch,
        script_exec_ext=script_exec,
        score=score,
        verdict=verdict,
        findings=findings,
        nested=[]
    )

def scan_one(data: bytes, fname: str, depth: int = 0, max_depth: int = 1) -> ScanResult:
    res = analyze_bytes(data, fname)
    # If ZIP and we allow one level of recursion, scan contained files
    if res.filetype == "ZIP" and depth < max_depth:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                members = safe_zip_members(zf)
                for zi in members:
                    try:
                        child_bytes = zf.read(zi)
                        child_res = scan_one(child_bytes, f"{fname}:{zi.filename}", depth + 1, max_depth)
                        res.nested.append(asdict(child_res))
                        # Propagate high severity from children
                        if child_res.score >= THRESHOLDS["suspicious"]:
                            res.findings.append(Finding(
                                "Suspicious item in archive",
                                0,
                                f"{zi.filename} → {child_res.verdict} ({child_res.score})"
                            ))
                    except Exception as e:
                        res.findings.append(Finding("Archive member error", 0, f"{zi.filename}: {e}"))
        except zipfile.BadZipFile:
            res.findings.append(Finding("Corrupt ZIP", 0, "Could not parse archive"))
    return res


# ============== Quarantine (optional) ==============

def quarantine_file(path: str):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    base = os.path.basename(path)
    dst = os.path.join(QUARANTINE_DIR, base)
    try:
        os.replace(path, dst)
        return True, dst
    except Exception as e:
        return False, str(e)


# ============== Reporting ==============

def print_report(results: List[ScanResult]):
    # Per-file
    for r in results:
        print("="*72)
        print(f"File: {r.filename}")
        print(f"- Size:         {r.size} bytes")
        print(f"- SHA256:       {r.sha256}")
        print(f"- Type/MIME:    {r.filetype} / {r.mimetype}")
        print(f"- Entropy:      {r.entropy:.2f}")
        print(f"- Verdict:      {r.verdict}  (Score {r.score})")
        if r.findings:
            print("- Findings:")
            for f in r.findings:
                print(f"  • {f.name} (+{f.weight}): {f.detail}")
        if r.nested:
            print(f"- Nested items: {len(r.nested)} (see JSON below)")
        print()

    # Summary
    counts = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    print("="*72)
    print("Summary:")
    for k in ["Malicious","High Risk","Suspicious","Caution","Likely Clean"]:
        if k in counts:
            print(f"- {k}: {counts[k]}")
    print("="*72)

def results_to_json(results: List[ScanResult]) -> str:
    return json.dumps([asdict(r) for r in results], indent=2)


# ============== Colab interaction ==============

def run_scanner():
    print("Upload files to scan (you can select multiple).")
    uploaded = files.upload()
    results: List[ScanResult] = []
    for name, data in uploaded.items():
        clear_output(wait=True)
        print(f"Scanning: {name} ({len(data)} bytes)")
        res = scan_one(data, name, depth=0, max_depth=1)
        results.append(res)

        # Optional quarantine for high-risk/malicious files (moves within Colab VM)
        if QUARANTINE and res.score >= THRESHOLDS["high"]:
            if os.path.exists(name):
                ok, msg = quarantine_file(name)
                tag = "OK" if ok else f"Failed: {msg}"
                print(f"Quarantine: {tag}")

    clear_output(wait=True)
    print_report(results)
    print("\nJSON report (collapsed): assign to a variable if needed, e.g., `report_json = results_to_json(results)`")
    return results

# Run
results = run_scanner()
