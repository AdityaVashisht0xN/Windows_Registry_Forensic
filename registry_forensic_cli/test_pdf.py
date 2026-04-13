import subprocess
import os

html_path = os.path.abspath("reports/registry_forensic_report.html")
pdf_path = os.path.abspath("reports/registry_forensic_report.pdf")

edge_paths = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
]

edge_exe = None
for p in edge_paths:
    if os.path.exists(p):
        edge_exe = p
        break

if not edge_exe:
    print("Microsoft Edge not found.")
else:
    print(f"Using Edge: {edge_exe}")
    edge_cmd = [
        edge_exe,
        "--headless",
        "--disable-gpu",
        f"--print-to-pdf={pdf_path}",
        html_path
    ]
    
    result = subprocess.run(edge_cmd, capture_output=True, text=True, check=False)
    print(f"Return code: {result.returncode}")
    print(f"Stdout: {result.stdout}")
    print(f"Stderr: {result.stderr}")
    
    if os.path.exists(pdf_path):
        print(f"PDF successfully created at {pdf_path}")
    else:
        print("PDF was not created.")
