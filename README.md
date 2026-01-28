# CTF Tools Auto-Installer for Ubuntu/Debian

Automated installation script for essential Capture The Flag (CTF) tools on Ubuntu and Debian-based Linux distributions.

## 🚀 Quick Installation

### Method 1: One-line Install (curl)
```bash
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/install_ctf_tools.sh | sudo bash
```

### Method 2: One-line Install (wget)
```bash
wget -qO- https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/install_ctf_tools.sh | sudo bash
```

### Method 3: Download and Run
```bash
# Download the script
wget https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/install_ctf_tools.sh

# Make it executable
chmod +x install_ctf_tools.sh

# Run it with sudo
sudo ./install_ctf_tools.sh
```

## 📋 What Gets Installed

This script automatically installs and configures the following categories of tools:

### 🔍 Reconnaissance & OSINT
- nmap - Network scanner
- masscan - Fast port scanner
- Sublist3r - Subdomain enumeration
- theHarvester - Information gathering

### 🌐 Web Exploitation
- SQLmap - SQL injection tool
- Nikto - Web server scanner
- dirb - Web content scanner
- gobuster - Directory/file brute-forcing
- ffuf - Fast web fuzzer
- wfuzz - Web application fuzzer

### 💾 Binary Exploitation & PWN
- pwntools - CTF framework
- pwndbg - GDB enhancement
- ROPgadget - ROP exploit tool
- checksec - Binary security checker
- one_gadget - One-shot RCE finder

### 🔧 Reverse Engineering
- radare2 - Reverse engineering framework
- binwalk - Firmware analysis
- apktool - Android APK tool
- strings - Extract text from binaries
- objdump - Object file dumper

### 🔐 Cryptography
- hashcat - Password recovery
- John the Ripper - Password cracker
- RsaCtfTool - RSA attack tool
- hash-identifier - Hash type identifier

### 🔬 Forensics
- Wireshark (tshark) - Network analyzer
- tcpdump - Packet capture
- foremost - File carving
- scalpel - File carving
- exiftool - Metadata extraction
- volatility3 - Memory forensics

### 🖼️ Steganography
- steghide - Hide data in files
- stegcracker - Steghide brute-force
- zsteg - PNG/BMP steganography
- stegseek - Fast steghide cracker

### 🔓 Password Cracking
- hydra - Network login cracker
- medusa - Parallel password cracker
- fcrackzip - ZIP password cracker

### ⬆️ Privilege Escalation
- LinPEAS - Linux privilege escalation
- pspy - Process monitoring

### 🎯 Exploitation Frameworks
- Metasploit (optional) - Penetration testing framework

### 🛠️ Miscellaneous
- searchsploit - Exploit database search
- jq - JSON processor
- Python libraries (requests, pwntools, z3-solver, angr, etc.)

## 📦 System Requirements

- **OS**: Ubuntu 18.04+ or Debian 10+
- **RAM**: 2GB minimum (4GB+ recommended)
- **Disk Space**: 5-10GB for all tools
- **Permissions**: Root/sudo access required

## ⚙️ Features

- ✅ Automatic dependency resolution
- ✅ Color-coded installation progress
- ✅ Error handling and logging
- ✅ Skip already installed tools
- ✅ Optional Metasploit installation
- ✅ PATH configuration for Go tools
- ✅ Clean installation with auto-cleanup

## 🎯 Usage

After installation, all tools are available system-wide. Simply type the tool name in your terminal:

```bash
# Examples
nmap -sV target.com
sqlmap -u "http://target.com/page?id=1"
gobuster dir -u http://target.com -w /path/to/wordlist
pwntools
```

## 🔄 Updating Tools

To update installed tools, simply re-run the script:

```bash
sudo ./install_ctf_tools.sh
```

The script will skip already installed tools and update where possible.

## 🗑️ Uninstalling

To remove installed tools, you can use:

```bash
# For apt-installed tools
sudo apt remove <tool-name>

# For manually installed tools
sudo rm -rf /opt/<tool-directory>
sudo rm /usr/local/bin/<tool-name>
```

## 🐛 Troubleshooting

### Permission Denied
Make sure you're running with sudo:
```bash
sudo ./install_ctf_tools.sh
```

### Network Issues
If downloads fail, check your internet connection and try again.

### Missing Dependencies
The script handles dependencies automatically. If issues persist:
```bash
sudo apt update
sudo apt upgrade -y
```

### Tool Not in PATH
Restart your terminal or run:
```bash
source ~/.bashrc
```

## 📚 Additional Resources

### Learning Platforms
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)
- [PicoCTF](https://picoctf.org/)
- [OverTheWire](https://overthewire.org/)

### Documentation
- [CTF Field Guide](https://trailofbits.github.io/ctf/)
- [CTF 101](https://ctf101.org/)
- [pwntools Docs](https://docs.pwntools.com/)

### YouTube Channels
- LiveOverflow
- IppSec
- John Hammond
- PwnFunction

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only. Always obtain proper authorization before testing systems you don't own. Unauthorized access to computer systems is illegal.

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new tools
- Submit pull requests
- Improve documentation

## 📝 License

This project is released under the MIT License. See LICENSE file for details.

## 🙏 Credits

Thanks to all the tool developers and the cybersecurity community for creating these amazing tools.

---

**Happy Hacking! 🚀**

*Last Updated: January 2026*
