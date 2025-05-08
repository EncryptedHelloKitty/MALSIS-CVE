# MALSIS-CVE

MALSIS-CVE is an automated malware analysis tool that creates a bridge between dynamic analysis, MITRE ATT&CK techniques, and potential CVE vulnerabilities. It submits samples to a Cuckoo sandbox, analyzes the behavior, and maps indicators to security frameworks to provide actionable intelligence.

## 🔍 Overview

MALSIS-CVE provides security analysts with:

- Automated malware sample submission to Cuckoo sandbox
- Extraction of behavioral indicators from sandbox reports
- Mapping of indicators to MITRE ATT&CK techniques 
- Identification of potentially relevant CVEs
- HTML report generation with risk assessment

## 📋 Prerequisites

- Python 3.6+
- A running [Cuckoo Sandbox](https://cuckoosandbox.org/) instance
- MITRE ATT&CK Enterprise database (local copy)
- NVD CVE database (local copy)

## 🧩 Dependencies

```
requests
scikit-learn
jinja2
```

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/malsis-cve.git
   cd malsis-cve
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Download the MITRE ATT&CK Enterprise database:
   ```bash
   curl -o enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
   ```

4. Download and prepare a CVE database (or use the included one if provided):
   ```bash
   # Example script to download recent CVEs would go here
   python download_cves.py
   ```

5. Configure your environment variables:
   ```bash
   export CUCKOO_API="http://your-cuckoo-instance:8090"
   export CUCKOO_TOKEN="your-api-token"
   ```

## 🚀 Usage

Basic usage:
```bash
python cve.py --file /path/to/malware_sample.exe
```

Additional options:
```bash
python cve.py --file /path/to/malware_sample.exe --cves custom_cve_db.json --top 20
```

### Parameters

- `--file`: Path to the malware sample to analyze (required)
- `--cves`: Path to the CVE database JSON file (default: nvd_cves.json)
- `--top`: Number of top CVEs to include in the report (default: 10)

## 📊 Output

The tool generates an HTML report (`final_report.html`) containing:
- Extracted indicators mapped to MITRE ATT&CK techniques
- Top potentially relevant CVEs with severity scores
- Risk assessment visualization

## 🔄 Pipeline Flow

1. Submit sample to Cuckoo Sandbox
2. Wait for analysis to complete
3. Download and parse the Cuckoo report
4. Extract behavioral indicators
5. Map indicators to MITRE ATT&CK techniques
6. Identify relevant CVEs based on extracted data
7. Generate a comprehensive HTML report

## 📝 Example

```bash
python cve.py --file malicious_pdf.pdf --top 15
```

This will:
1. Submit `malicious_pdf.pdf` to your configured Cuckoo instance
2. Wait for the analysis to complete (with a default timeout)
3. Extract behavioral indicators from the generated report
4. Map these to MITRE ATT&CK techniques
5. Find the top 15 related CVEs
6. Generate and open a final HTML report

## 🔧 Configuration

The following environment variables can be used to configure the tool:

- `CUCKOO_API`: URL of your Cuckoo API (default: http://localhost:8090)
- `CUCKOO_TOKEN`: Authentication token for Cuckoo API
- `DEFAULT_TIMEOUT`: Maximum time to wait for analysis (default: 300 seconds)

## 🛡️ Security Considerations

- This tool is intended for use in secured, isolated environments
- Never analyze malware on production systems or networks
- Always ensure your Cuckoo sandbox is properly isolated

## 🙏 Acknowledgments

- [Cuckoo Sandbox](https://cuckoosandbox.org/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [National Vulnerability Database](https://nvd.nist.gov/)
