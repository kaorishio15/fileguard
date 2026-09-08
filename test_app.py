import io
import pytest
from app import app
from engine import analyze_file, calculate_entropy


# --- 1. engine unit tests ---

def test_calculate_entropy_zero_and_uniform():
    assert calculate_entropy(b"") == 0.0
    # single byte repeated has 0 entropy (no randomness)
    assert calculate_entropy(b"AAAAAAA") == 0.0


def test_analyze_clean_file():
    content = b"Hello world! This is a benign text file."
    result = analyze_file(content, "document.txt")

    assert result["filename"] == "document.txt"
    assert result["risk_score"] == 0
    assert result["severity"] == "LOW"
    assert len(result["indicators"]) == 0


def test_double_extension_detection():
    content = b"echo 'malicious payload'"
    result = analyze_file(content, "invoice.pdf.exe")

    rules = [ind["rule"] for ind in result["indicators"]]
    assert "DOUBLE_EXTENSION" in rules
    assert result["risk_score"] >= 35


def test_extension_mismatch_detection():
    # pe header bytes (MZ) disguised as a .pdf extension
    pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
    result = analyze_file(pe_header, "report.pdf")

    rules = [ind["rule"] for ind in result["indicators"]]
    assert "EXT_MISMATCH" in rules
    assert result["risk_score"] >= 40


def test_pdf_embedded_script_detection():
    pdf_with_js = b"%PDF-1.4 /JavaScript (app.alert('XSS'))"
    result = analyze_file(pdf_with_js, "sample.pdf")

    rules = [ind["rule"] for ind in result["indicators"]]
    assert "EMBEDDED_SCRIPT" in rules
    assert result["risk_score"] >= 30


# --- 2. flask api integration tests ---

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_route(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"FileGuard" in response.data


def test_scan_api_no_file(client):
    response = client.post("/api/scan")
    assert response.status_code == 400
    assert response.get_json()["error"] == "No file uploaded"


def test_scan_api_valid_file(client):
    data = {
        "file": (io.BytesIO(b"MZ\x90\x00Fake Exe Content"), "fake_invoice.pdf.exe")
    }
    response = client.post("/api/scan", data=data, content_type="multipart/form-data")
    
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["filename"] == "fake_invoice.pdf.exe"
    assert json_data["severity"] in ["HIGH", "CRITICAL"]
    assert len(json_data["indicators"]) >= 2  # double_extension + ext_mismatch