# NetHawk Scanner

A network vulnerability assessment tool I built for penetration testing and security audits. This isn't some toy project - it's designed to handle real network scans and generate proper reports that you can actually present to clients or management.

## What it does

NetHawk Scanner performs comprehensive network security assessments. It discovers live hosts, scans ports, identifies services, detects vulnerabilities, and generates professional PDF reports. The interface is clean and functional - no flashy graphics, just the tools you need to get the job done.

The scanner integrates with nmap for the heavy lifting and maintains a local database of scan results. Vulnerability detection works by matching discovered services against CVE databases and known vulnerability patterns. Everything gets logged properly so you can track what happened during each scan.

## Getting it running

Dead simple. Just need Python 3.7+ and nmap installed.

**One command does everything:**
```bash
python3 run.py
```

That's it. The script automatically creates a virtual environment, installs all requirements, and launches the app.

For full scan capabilities (recommended):
```bash
sudo python3 run.py
```

The application will open in a new window with the NetHawk Scanner interface.

**Manual setup (if you want control):**
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Run the app
python3 main.py
```

On Kali Linux it should work immediately since nmap is already installed.

## How to use it

The interface has two main panels. Left side is for configuring your scan, right side shows results.

### Basic scanning

1. Enter your target IPs in the target field. You can use single IPs, ranges like 192.168.1.1-50, or CIDR notation like 192.168.1.0/24.

2. Pick a scan profile. I included several presets:
   - Quick scan hits common ports fast
   - Comprehensive scan does everything but takes longer  
   - Stealth scan tries to avoid detection
   - Web ports focuses on HTTP/HTTPS services

3. Adjust advanced options if needed. Service detection, OS fingerprinting, and script scanning give you more information but slow things down.

4. Hit start and watch it work.

### Results and reporting

The results panel has tabs for hosts, ports, vulnerabilities, and scan history. You can filter results, sort columns, and export data in CSV, JSON, or XML formats.

The real value is in the PDF reports. Click "Generate Report" and you get a professional document with executive summary, technical findings, network overview, and remediation recommendations. I spent time making sure these reports look good enough for client presentations.

## What's under the hood

The application uses PyQt5 for the interface and SQLite for data storage. All scanning goes through python-nmap, which is just a wrapper around the real nmap binary. Vulnerability detection combines service fingerprinting with CVE database lookups.

I structured the code so it's easy to extend. The database schema handles complex scan data, the GUI components are modular, and the scanning engine supports different scan types and configurations.

## Legal stuff

This tool is for authorized testing only. Don't scan networks you don't own or don't have permission to test. I built this for legitimate security professionals, not for causing trouble.

Most countries have laws about unauthorized network scanning, and some organizations consider any port scan an attack. Always get proper authorization before running security assessments.

## Troubleshooting

If something goes wrong, check these common issues:

**Nmap not found**: Install nmap with your package manager. On Debian/Ubuntu systems: `sudo apt-get install nmap`

**Permission errors**: Some scan types need root privileges. Run with sudo for full functionality.

**PyQt5 problems**: Install the system package: `sudo apt-get install python3-pyqt5`

**Virtual environment issues**: Delete the venv folder and let run.py recreate it.

The application writes detailed logs to data/logs/ if you need to debug something specific.

## Technical details

- Database: SQLite with proper schema for scan data
- GUI: PyQt5 with custom dark theme
- Scanning: Multi-threaded nmap integration  
- Reports: ReportLab PDF generation
- Export: CSV, JSON, XML formats
- Logging: Rotating log files with audit trail

I tested this on Kali Linux but it should work on any modern Linux system with Python 3.7+. The code is clean and well-documented if you want to modify or extend it.

## Testing

Run the test suite to verify everything works:

```bash
python3 test_application.py
```

This tests database operations, vulnerability detection, report generation, and other critical components. All tests should pass before using the scanner for real assessments.

## Background

I built this because existing tools either cost too much, have terrible interfaces, or don't generate the kind of reports clients actually want to see. NetHawk Scanner bridges that gap - it's functional, professional, and gets the job done without unnecessary complexity.

The vulnerability detection isn't perfect and you shouldn't rely on it as your only security measure. But it catches common issues and gives you a solid starting point for manual verification. Always validate findings manually before including them in official reports.

This represents several months of development and testing on real networks. I use it regularly for my own security assessments and it hasn't let me down yet.