<div align="center"> <img src="../image/zwyrm.png" alt="ZWYRM Logo" width="200"/> </div>

# 🛡️ ZWyrm AntiVirus v2.0

![ZWyrm AntiVirus](https://img.shields.io/badge/ZWyrm-AntiVirus-blue)
![Python](https://img.shields.io/badge/Python-3.7+-green)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-orange)

**ZWyrm** (pronounced *"worm"*) is a lightweight **Python-based antivirus and security framework for Linux systems**.

It provides tools for:

- malware detection
- file system scanning
- real-time monitoring
- quarantine management
- automatic signature updates

Version **2.0** improves modularity, configuration management, and scanning performance while maintaining low system resource usage.

## 📁 Project Structure (v2)

The following table describes the structure of the `v2` directory:

| Path | Description |
|-----|-------------|
| `cli/` | Command-line interface modules |
| `core/` | Core antivirus engine (scanner and quarantine logic) |
| `database/` | Malware signature database and update system |
| `logs/` | Log files generated during scans and system operations |
| `modules/` | Optional modules such as real-time monitoring |
| `utils/` | Utility functions (configuration loader, logger, helpers) |
| `config.yaml` | Main configuration file |
| `requirements.txt` | Python dependency list |
| `zwyrm.py` | Main entry point of the application |

## 🚀 Features

ZWyrm v2 introduces a modular and flexible architecture with the following capabilities:

### 🔍 Malware Scanning
- Scan **single files**
- Scan **entire directories**
- Perform **full system scans**

### ⚡ Multiple Scan Modes
- **Quick Scan** – scans common malware locations
- **Deep Scan** – detailed scanning process
- **Full System Scan** – scans the entire filesystem

### 🛡️ Real-Time Protection
- Optional real-time monitoring
- Detects suspicious file activity
- Uses `pyinotify` for filesystem event monitoring

### 📦 Quarantine System
- Isolates detected malicious files
- Restore or permanently remove quarantined items

### 🔄 Automatic Signature Updates
- Updates malware definitions from the signature database

### 📊 Logging System
- Detailed logs for all scanning and quarantine actions

### ⚙️ Configurable
- Fully customizable behavior through `config.yaml`

### 🧩 Modular Architecture
- Security modules can be added or extended easily

## 🔧 Installation

### Quick Install

# Clone repository
git clone https://github.com/ZDrago-afk/ZWyrm.git
cd ZWyrm

# Navigate to v2
cd v2

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x zwyrm.py

# Optional: create system-wide command
sudo ln -s $(pwd)/zwyrm.py /usr/local/bin/zwyrm

## 🎮 Usage

Basic Commands

zwyrm help
zwyrm version
zwyrm info

# Scan directory
zwyrm scan ~/Downloads

# Quick scan
zwyrm scan -q ~/Downloads

# Full system scan
zwyrm scan -f /

# Scan and quarantine detected threats
zwyrm scan -r ~/Downloads

# Verbose scan output
zwyrm scan -v /path/to/file

## 🔄 Signature Updates

Update malware signatures:

zwyrm update

Force update:

zwyrm update --force

Regular updates improve malware detection accuracy.

## 📦 Quarantine Management

# List quarantined files
zwyrm quarantine --list

# Restore file from quarantine
zwyrm quarantine --restore 3

# Permanently delete quarantined file
zwyrm quarantine --remove 5

# Clear all quarantine entries
zwyrm quarantine --clear

## 🛡️ Real-Time Protection

# Start monitoring
zwyrm realtime --start

# Check status
zwyrm realtime --status

# Stop monitoring
zwyrm realtime --stop

Requires installation of:

pip install pyinotify

## ⚙️ Configuration

ZWyrm is configured through `config.yaml` inside the `v2` directory.

Example configuration:

zwyrm:

  debug_mode: false
  
  log_level: INFO
  
  max_file_size: 10485760
  
  exclude_paths:
  
    - /proc
    
    - /sys
    
    - /dev
    
  scan_extensions:
  
    - .exe
    
    - .bin
    
    
    - .sh
    
    - .py
  
  auto_update: true
  
  update_interval: 86400


## 📊 Logging

All scanning and quarantine activities are logged in the `logs/` directory.

View logs in real-time:

tail -f logs/scanner.log

tail -f logs/quarantine.log

## 🔒 Security Considerations

- Avoid running ZWyrm as **root unless required**
- Keep malware signatures **updated**
- Maintain **regular system backups**
- Restrict access to quarantine directories

## 🐛 Troubleshooting

Common Issues

1. Import error during startup
pip install -r requirements.txt

2. Real-time protection unavailable
pip install pyinotify

3. Permission denied while scanning
ls -la /path/to/scan

4. Signature update failure

ping github.com
zwyrm update --force

## 🤝 Contributing

Contributions are welcome.

Steps:

1. Fork the repository
2. Create a new branch
3. Commit your changes
4. Push to your fork
5. Submit a Pull Request

## 📝 License

This project is licensed under the **MIT License**.

See the `LICENSE` file for details.

## ⚠️ Disclaimer

ZWyrm is provided **as-is without warranties**.

Always maintain backups and use additional security layers for production systems.

