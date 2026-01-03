# ZWyrm_v0 - Red-Team–Informed Behavioral Antivirus for Linux

![ZWyrm Banner](assets/zwyrm.png)

**ZWyrm** is a next-generation behavioral antivirus system designed for Linux environments. Built with insights from red-team operations, it focuses on detecting and responding to suspicious behavior patterns rather than traditional signature-based detection.


## 🚀 Features

- **Behavioral Process Monitoring**: Real-time analysis of running processes for suspicious activities
- **File Integrity Monitoring (FIM)**: Detect unauthorized changes to critical system files
- **Network Anomaly Detection**: Monitor for connections to known suspicious ports
- **MITRE ATT&CK Mapping**: All alerts are mapped to relevant MITRE ATT&CK techniques
- **Dual Operational Modes**: 
  - **Safe Mode**: Alert-only (recommended for initial deployment)
  - **Enforce Mode**: Automatic response actions
- **Comprehensive Logging**: Structured logging with rotation and archiving


## 📋 Prerequisites

- **Operating System**: Linux (Tested on Ubuntu 20.04+, Debian 11+, CentOS 8+)
- **Python**: 3.9 or higher
- **Permissions**: Root/administrative privileges for full functionality

## 🛠️ Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/zwyrm.git
cd zwyrm

# Run the installation script
sudo ./scripts/install.sh
```

### Manual Installation

#### 1. Install Python dependencies
sudo pip3 install -r requirements.txt

#### 2. Create necessary directories
sudo mkdir -p /opt/zwyrm
sudo mkdir -p /var/log/zwyrm
sudo mkdir -p /etc/zwyrm

#### 3. Copy files
sudo cp -r . /opt/zwyrm/

#### 4. Set permissions
sudo chmod 755 /opt/zwyrm/main.py
sudo chmod 644 /opt/zwyrm/config/zwyrm.yaml

#### 5. Install systemd service (optional)
sudo cp systemd/zwyrm.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable zwyrm.service

### Docker Installation

# Build the Docker image
docker build -t zwyrm .

# Run with configuration volume
docker run -d \
  --name zwyrm \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_PTRACE \
  -v /etc/zwyrm:/etc/zwyrm \
  -v /var/log/zwyrm:/var/log/zwyrm \
  zwyrm


## 🔍 Detection Capabilities

### 1. Process Behavior Analysis
- Execution from suspicious paths (`/tmp`, `/var/tmp`, `/dev/shm`)
- Root privilege escalation anomalies
- Unusual parent-child process relationships

### 2. File Integrity Monitoring (FIM)
- SHA-256 hash verification of critical files
- Real-time modification detection
- Baseline integrity maintenance

### 3. Network Anomaly Detection
- Connections to known malicious ports
- Suspicious outbound/inbound traffic patterns
- Process-to-network correlation

### 4. MITRE ATT&CK Mapping
All detections are mapped to relevant MITRE ATT&CK techniques:

| Alert Type              | MITRE Technique | Description                             |
|-------------------------|-----------------|-----------------------------------------|
| suspicious_execution    | T1059           | Command and Scripting Interpreter        |
| privilege_escalation    | T1068           | Exploitation for Privilege Escalation   |
| file_tampering          | T1547           | Autostart Execution                     |
| network_anomaly         | T1071           | Application Layer Protocol              |


## 🛡️ Response Actions

### Safe Mode (Default)
- **Alerts only** — no automatic actions
- Logs all suspicious activities
- Ideal for monitoring, learning baseline behavior, and evaluation

### Enforce Mode
- **Automatic termination** of malicious processes
- Immediate response to detected threats
- Recommended for production use **after thorough testing**


## 🧪 Testing

# Create a suspicious process in /tmp (should trigger alert)
echo "sleep 30" > /tmp/test.sh
chmod +x /tmp/test.sh
/tmp/test.sh &

# Check ZWyrm logs for detection
tail -f /var/log/zwyrm/zwyrm.log

### Common Issue: Import errors

# Fix Python path
export PYTHONPATH="$PYTHONPATH:/opt/zwyrm"

### Common Issue: Permission denied

# Run with sudo
sudo python3 main.py

### Common Issue: Missing dependencies

# Install all requirements
pip3 install -r requirements.txt

### Common Issue: Service won't start

# Check service status
sudo systemctl status zwyrm

# View detailed logs
sudo journalctl -xe

### Debug Mode

# Enable debug logging in zwyrm.yaml
logging:
  level: DEBUG


## 📁 Project Structure

| Folder/File         | Description                             |
|--------------------|-----------------------------------------|
| `main.py`          | Entry point of ZWyrm                     |
| `cli/cli.py`       | Command-line interface implementation    |
| `cli/__init__.py`  | CLI package definition                   |
| `core/engine.py`   | Main engine                              |
| `core/detector.py` | Detection logic                           |
| `core/monitor.py`  | Process monitoring                        |
| `core/responder.py`| Response actions                          |
| `core/fim.py`      | File integrity monitor                     |
| `core/network.py`  | Network monitoring                        |
| `core/logger.py`   | Logging setup                             |
| `core/mitre.py`    | MITRE ATT&CK mapping                      |
| `config/zwyrm.yaml`| Main configuration                         |
| `utils/banner.py`  | ASCII banner                              |
| `scripts/install.sh`| Installation script                       |
| `scripts/uninstall.sh`| Uninstallation script                   |
| `systemd/zwyrm.service`| Systemd service file                   |
| `assets/zwyrm.png` | Logo                                      |
| `requirements.txt` | Python dependencies                       |
| `setup.py`         | Python package setup                       |
| `README.md`        | Project documentation                      |


## 🤝 Contributing & Development Setup

| Topic                   | Instructions / Details                                                                 |
|-------------------------|---------------------------------------------------------------------------------------|
| Contributing Guidelines  | 1. Fork the repository <br> 2. Create a feature branch <br> 3. Commit changes <br> 4. Push to branch <br> 5. Open a Pull Request |
| Development Setup        | 1. Clone the repo: `git clone https://github.com/yourusername/zwyrm.git` <br> 2. Create virtual environment: `python3 -m venv venv` <br> 3. Activate environment: `source venv/bin/activate` <br> 4. Install dependencies: `pip install -r requirements.txt` <br> 5. Run tests: `python -m pytest tests/` <br> 6. Run in dev mode: `python main.py --dev` |


## 📄 License & Disclaimer

### License
This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

### Disclaimer
ZWyrm is designed for **security monitoring and educational purposes**.  
Use at your own risk. The authors are **not responsible** for any damage caused by misuse or misconfiguration.  

**Important:** Always run in **Safe Mode first** and thoroughly test in a controlled environment before enabling **Enforce Mode** in production.


## 🌟 Acknowledgments & Support

### Acknowledgments
- Inspired by various open-source security tools and frameworks
- MITRE ATT&CK framework for comprehensive threat modeling
- The Linux community for invaluable resources and tools




