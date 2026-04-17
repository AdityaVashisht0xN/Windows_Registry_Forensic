[WRFA_README.docx](https://github.com/user-attachments/files/26812204/WRFA_README.docx)
#WRFA - Windows Registry Forensic Analyzer#
WRFA (Windows Registry Forensic Analyzer) is a forensic tool designed to analyze Windows Registry hive files and extract critical system and user activity artifacts.

The tool operates entirely in offline and read-only mode, ensuring that the original evidence remains intact and unmodified.
Features


•	Read-only forensic analysis (evidence integrity preserved)
•	CSV, HTML, and PDF report generation
•	Risk classification (HIGH / MEDIUM / INFO)
•	SHA-256 hash verification
•	Extraction of multiple registry artifacts

#Extracted Artifacts

The tool extracts a wide range of artifacts from registry hives. The availability of artifacts may vary from system to system depending on user activity and system configuration. It is not guaranteed that all artifacts will be present on every system.
•	User Activity: Recent Documents, Open/Save Dialog History, UserAssist (executed programs), Explorer Typed Paths
•	System Activity: USB Device History, Mounted Devices, Installed Software, Windows Services
•	Network: Network Interfaces (GUID-based)
•	Persistence & Security: Run Keys (auto-start programs), Local Users (SAM)
•	Advanced Artifacts: ShellBags (folder navigation history), Folder View History
•	DEFAULT hive provides baseline system behavior such as default startup entries and explorer configuration

#Supported Registry Hives
•	SYSTEM
•	SOFTWARE
•	SAM
•	SECURITY
•	DEFAULT
•	NTUSER.DAT
•	UsrClass.dat

#Evidence Acquisition
For meaningful results, proper forensic acquisition is required.

Recommended Method:
- Disk Imaging (using tools like FTK Imager or dd)
- Extract registry hives from the image

#Required Folder Structure:

evidence/

├── SYSTEM
├── SOFTWARE
├── SAM
├── SECURITY
├── DEFAULT
├── NTUSER.DAT
└── UsrClass.dat

#Installation
1. Clone Repository
git clone https://github.com/AdityaVashisht0xN/Windows_Registry_Forensic.git
2. Install Dependencies
pip install python-registry pandas colorama
Usage
Step 1: Place evidence files inside the evidence/ folder.
Step 2: Run the tool:
python registry_forensic_cli.py
Step 3: Choose an option:
1 - Verify Evidence Hashes
2 - Generate Forensic Reports
3 - Exit

#Output Reports
CSV - Structured artifact data
HTML - Professional forensic report
PDF - Printable report

#Limitations
•	Full file paths may not always be available
•	OpenSaveMRU data is binary and partially decoded
•	SAM does not provide complete login timestamps
•	Registry analysis alone does not provide full forensic visibility

#Tool Screenshot



# Digital_Forensic
