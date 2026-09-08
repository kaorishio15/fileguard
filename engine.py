import hashlib
import math
import zipfile
import io
from collections import Counter

MAGIC_SIGNATURES = [
    (b"MZ", "application/x-dosexec", "PE Executable"),
    (b"\x7fELF", "application/x-executable", "ELF Executable"),
    (b"%PDF", "application/pdf", "PDF Document"),
    (b"PK\x03\x04", "application/zip", "ZIP Archive"),
]

EXECUTABLE_EXTS = {".exe", ".dll", ".vbs", ".bat", ".cmd", ".ps1", ".js", ".scr"}
DOCUMENT_EXTS = {".pdf", ".docx", ".xlsx", ".txt", ".png", ".jpg"}

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 2)

def analyze_file(file_bytes: bytes, filename: str) -> dict:
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    entropy = calculate_entropy(file_bytes)
    
    # magic byte type detection
    detected_mime = "application/octet-stream"
    for magic, mime, _ in MAGIC_SIGNATURES:
        if file_bytes.startswith(magic):
            detected_mime = mime
            break

    indicators = []
    score = 0

    # 1. double extension check
    parts = [p.lower() for p in filename.split(".") if p]
    if len(parts) >= 3 and f".{parts[-2]}" in DOCUMENT_EXTS and f".{parts[-1]}" in EXECUTABLE_EXTS:
        indicators.append({
            "rule": "DOUBLE_EXTENSION",
            "points": 35,
            "evidence": f"Double extension pattern detected: '.{parts[-2]}.{parts[-1]}'"
        })
        score += 35

    # 2. extension mismatch check
    ext = f".{parts[-1]}" if parts else ""
    if ext in DOCUMENT_EXTS and detected_mime in ["application/x-dosexec", "application/x-executable"]:
        indicators.append({
            "rule": "EXT_MISMATCH",
            "points": 40,
            "evidence": f"File claims extension '{ext}' but signature indicates an executable binary."
        })
        score += 40

    # 3. high entropy check
    if entropy > 7.2:
        indicators.append({
            "rule": "HIGH_ENTROPY",
            "points": 20,
            "evidence": f"High Shannon entropy ({entropy}/8.0) suggests compressed, packed, or encrypted payload."
        })
        score += 20

    # 4. pdf embedded script inspection
    if detected_mime == "application/pdf":
        text_sample = file_bytes.decode("latin-1", errors="ignore")
        if "/JavaScript" in text_sample or "/JS" in text_sample:
            indicators.append({
                "rule": "EMBEDDED_SCRIPT",
                "points": 30,
                "evidence": "PDF structure contains embedded JavaScript tags."
            })
            score += 30

    # 5. archive safety inspection
    if detected_mime == "application/zip" and zipfile.is_zipfile(io.BytesIO(file_bytes)):
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                for name in z.namelist():
                    if any(name.lower().endswith(x) for x in EXECUTABLE_EXTS):
                        indicators.append({
                            "rule": "ARCHIVE_CONTAINS_EXECUTABLE",
                            "points": 30,
                            "evidence": f"Archive contains script or executable payload: '{name}'"
                        })
                        score += 30
                        break
        except Exception:
            pass

    # final score & severity bounding
    final_score = min(score, 100)
    if final_score >= 75:
        severity = "CRITICAL"
    elif final_score >= 50:
        severity = "HIGH"
    elif final_score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "filename": filename,
        "sha256": sha256,
        "size": len(file_bytes),
        "detected_type": detected_mime,
        "entropy": entropy,
        "risk_score": final_score,
        "severity": severity,
        "indicators": indicators,
    }