# ZWyrm AntiVirus v1.0

![ZWyrm AntiVirus](https://img.shields.io/badge/ZWyrm-AntiVirus-blue)
![Python Version](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

**ZWyrm** (pronounced "worm") is a lightweight, Python-based antivirus and security framework for Linux systems. It provides on-demand scanning, real-time protection, quarantine management, and automatic signature updates.

## 📁 Repository Structure (v1)

This repository contains the complete source code for ZWyrm v1:

ZWyrm/
├── cli/               # Command-line interface modules
├── core/              # Core scanning and quarantine engine
├── database/          # Signature databases and management
├── logs/              # Application log files
├── modules/           # Additional modules (real-time protection)
├── utils/             # Utility functions (config, logger)
├── config.yaml        # Main configuration file
├── install.sh         # Installation script
├── requirements.txt   # Python dependencies
└── zwyrm.py           # Main application entry point

## 🚀 Features

- **File & Directory Scanning** – Scan individual files, directories, or perform full system scans
- **Multiple Scan Modes** – Quick scan, deep scan, and full system scan options
- **Real-time Protection** – Monitor file system events with `pyinotify` (optional module)
- **Quarantine Management** – Isolate, restore, or permanently delete detected threats
- **Automatic Signature Updates** – Keep virus definitions up-to-date via the `database/` module
- **Comprehensive Logging** – Track all scanning and quarantine activities in `logs/`
- **User-friendly CLI** – Clear, colorful command-line interface from the `cli/` package
- **Configurable** – Customize behavior via `config.yaml`
- **Low Resource Usage** – Written in Python, minimal system impact

## 📋 Requirements

- Python 3.7 or higher
- Linux operating system (tested on Ubuntu, Debian, Fedora, CentOS)
- Optional: `pyinotify` for real-time protection (see `requirements.txt`)

## 🔧 Installation

### Quick Install (Recommended)

# Clone the repository
git clone https://github.com/ZDrago-afk/ZWyrm.git
cd ZWyrm

# Run the installation script
chmod +x install.sh
./install.sh

This will:
- Install required Python dependencies from `requirements.txt`
- Set up the complete directory structure
- Configure the application using `config.yaml`
- Make the `zwyrm` command available system-wide

### Manual Installation

# Install Python dependencies
pip install -r requirements.txt

# Make the main script executable
chmod +x zwyrm.py

# Optional: Create a symlink
sudo ln -s $(pwd)/zwyrm.py /usr/local/bin/zwyrm

## 🎮 Usage

### Basic Commands

zwyrm help
zwyrm version
zwyrm info

### Scanning

zwyrm scan ~/Downloads
zwyrm scan -q ~/Downloads
zwyrm scan -f /
zwyrm scan -r ~/Downloads
zwyrm scan -v /path/to/file

### Signature Updates

zwyrm update
zwyrm update --force

### Quarantine Management

zwyrm quarantine --list
zwyrm quarantine --restore 3
zwyrm quarantine --remove 5
zwyrm quarantine --clear

### Real-time Protection

zwyrm realtime --start
zwyrm realtime --status
zwyrm realtime --stop

## ⚙️ Configuration

ZWyrm is configured via `config.yaml` in the project root. Key settings include:

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

  ## 🛡️ Signature Database

The `database/` directory stores all virus signatures. ZWyrm uses a signature-based detection system with:

- Core signatures – Main threat database
- Daily updates – Incremental signature updates
- User-defined – Custom signatures you can add

To add custom signatures, edit the appropriate files in the `database/` directory.

## 📊 Logging

All activities are logged to the `logs/` directory:

# View scanner logs
tail -f logs/scanner.log

# View quarantine logs
tail -f logs/quarantine.log

## 🔒 Security Considerations

- Run as normal user – Avoid running ZWyrm as root unless necessary
- Regular updates – Keep signatures updated for maximum protection
- Quarantine isolation – Quarantined files are stored with restricted permissions
- Network security – Signature updates use HTTPS where possible

## 🐛 Troubleshooting

1. Import error during startup
pip install -r requirements.txt

2. Real-time protection not available
pip install pyinotify

3. Permission denied errors
ls -la /path/to/scan

4. Signature update fails

ping github.com
zwyrm update --force

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch
git checkout -b feature/amazing-feature

3. Commit your changes
git commit -m 'Add some amazing feature'

4. Push to the branch
git push origin feature/amazing-feature

5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- The Python community for excellent libraries
- Open source security researchers for signature databases
- All contributors and testers

⚠️ Disclaimer: ZWyrm is provided as-is without any warranties. Always maintain regular backups and use additional security measures for critical systems.

