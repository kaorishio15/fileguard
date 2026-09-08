import os
import zipfile

# create output folder for test samples
TEST_DIR = "test_files"
os.makedirs(TEST_DIR, exist_ok=True)

# 1. clean file (expected score: 0 - low)
with open(os.path.join(TEST_DIR, "benign_document.txt"), "wb") as f:
    f.write(b"This is a harmless plain text file for testing FileGuard.")

# 2. double extension trigger (expected score: 35 - medium)
with open(os.path.join(TEST_DIR, "invoice.pdf.exe"), "wb") as f:
    f.write(b"echo 'Simulated executable with double extension'")

# 3. extension mismatch trigger (expected score: 40 - medium)
# claims to be .pdf, but contains PE Header bytes (MZ)
with open(os.path.join(TEST_DIR, "report.pdf"), "wb") as f:
    f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")

# 4. high entropy trigger (expected score: 20 - low)
# random bytes yield near ~8.0 Shannon entropy
with open(os.path.join(TEST_DIR, "packed_payload.bin"), "wb") as f:
    f.write(os.urandom(2048))

# 5. pdf embedded script trigger (expected score: 30 - medium)
with open(os.path.join(TEST_DIR, "malicious_script.pdf"), "wb") as f:
    f.write(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /JavaScript (app.alert('XSS')) >>\nendobj")

# 6. zip containing executable trigger (expected score: 30 - medium)
zip_path = os.path.join(TEST_DIR, "archive_payload.zip")
with zipfile.ZipFile(zip_path, "w") as z:
    z.writestr("hidden_script.bat", "echo 'Malicious batch script inside zip'")

# 7. critical compound threat (triggers multiple rules: double ext + mismatch + high entropy)
with open(os.path.join(TEST_DIR, "urgent_invoice.pdf.exe"), "wb") as f:
    # mz magic bytes + 2kb of high-entropy random data
    f.write(b"MZ" + os.urandom(2048))

print(f"Generated 7 test files in './{TEST_DIR}/'")