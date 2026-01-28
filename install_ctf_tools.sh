#!/bin/bash

################################################################################
# CTF Tools Auto-Installer for Ubuntu/Debian
# Usage: curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/install_ctf_tools.sh | bash
# Or: wget -qO- https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/install_ctf_tools.sh | bash
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << "EOF"
   ____ _____ _____   _____           _     
  / ___|_   _|  ___| |_   _|__   ___ | |___ 
 | |     | | | |_      | |/ _ \ / _ \| / __|
 | |___  | | |  _|     | | (_) | (_) | \__ \
  \____| |_| |_|       |_|\___/ \___/|_|___/
                                             
  Automated Installer for Ubuntu/Debian
EOF
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] Please run as root or with sudo${NC}"
    exit 1
fi

# Detect Ubuntu/Debian
if [ ! -f /etc/debian_version ]; then
    echo -e "${RED}[!] This script is designed for Ubuntu/Debian systems${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Starting CTF Tools installation...${NC}\n"

# Update system
echo -e "${YELLOW}[*] Updating system packages...${NC}"
apt update -qq
apt upgrade -y -qq

# Install essential dependencies
echo -e "${YELLOW}[*] Installing essential dependencies...${NC}"
apt install -y \
    build-essential \
    git \
    curl \
    wget \
    vim \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    ruby \
    ruby-dev \
    golang-go \
    openjdk-11-jdk \
    gcc \
    g++ \
    make \
    cmake \
    gdb \
    nasm \
    netcat-traditional \
    socat \
    tmux \
    screen \
    tree \
    htop \
    unzip \
    p7zip-full \
    binutils \
    file \
    strace \
    ltrace \
    net-tools \
    dnsutils \
    tcpdump \
    2>/dev/null

echo -e "${GREEN}[✓] Essential dependencies installed${NC}\n"

# ========================================
# RECONNAISSANCE & OSINT
# ========================================
echo -e "${BLUE}[*] Installing Reconnaissance Tools...${NC}"

# Nmap
apt install -y nmap 2>/dev/null
echo -e "${GREEN}  ✓ nmap${NC}"

# Masscan
apt install -y masscan 2>/dev/null || echo -e "${RED}  ✗ masscan (skipped)${NC}"

# theHarvester
pip3 install theHarvester 2>/dev/null || echo -e "${RED}  ✗ theHarvester (skipped)${NC}"

# Sublist3r
if [ ! -d "/opt/Sublist3r" ]; then
    git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r 2>/dev/null
    pip3 install -r /opt/Sublist3r/requirements.txt 2>/dev/null
    ln -sf /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r 2>/dev/null
    echo -e "${GREEN}  ✓ Sublist3r${NC}"
else
    echo -e "${YELLOW}  ~ Sublist3r already installed${NC}"
fi

# ========================================
# WEB EXPLOITATION
# ========================================
echo -e "${BLUE}[*] Installing Web Exploitation Tools...${NC}"

# SQLmap
apt install -y sqlmap 2>/dev/null
echo -e "${GREEN}  ✓ sqlmap${NC}"

# Nikto
apt install -y nikto 2>/dev/null
echo -e "${GREEN}  ✓ nikto${NC}"

# dirb
apt install -y dirb 2>/dev/null
echo -e "${GREEN}  ✓ dirb${NC}"

# Gobuster
apt install -y gobuster 2>/dev/null || echo -e "${RED}  ✗ gobuster (skipped)${NC}"

# ffuf
go install github.com/ffuf/ffuf@latest 2>/dev/null || echo -e "${RED}  ✗ ffuf (skipped)${NC}"

# wfuzz
pip3 install wfuzz 2>/dev/null
echo -e "${GREEN}  ✓ wfuzz${NC}"

# ========================================
# BINARY EXPLOITATION & PWN
# ========================================
echo -e "${BLUE}[*] Installing Binary Exploitation Tools...${NC}"

# pwntools
pip3 install pwntools 2>/dev/null
echo -e "${GREEN}  ✓ pwntools${NC}"

# ROPgadget
pip3 install ROPgadget 2>/dev/null
echo -e "${GREEN}  ✓ ROPgadget${NC}"

# one_gadget
gem install one_gadget 2>/dev/null || echo -e "${RED}  ✗ one_gadget (skipped)${NC}"

# pwndbg (GDB plugin)
if [ ! -d "$HOME/pwndbg" ]; then
    git clone https://github.com/pwndbg/pwndbg "$HOME/pwndbg" 2>/dev/null
    cd "$HOME/pwndbg" && ./setup.sh 2>/dev/null
    echo -e "${GREEN}  ✓ pwndbg${NC}"
else
    echo -e "${YELLOW}  ~ pwndbg already installed${NC}"
fi

# checksec
apt install -y checksec 2>/dev/null || {
    wget https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec -O /usr/local/bin/checksec 2>/dev/null
    chmod +x /usr/local/bin/checksec
    echo -e "${GREEN}  ✓ checksec${NC}"
}

# ========================================
# REVERSE ENGINEERING
# ========================================
echo -e "${BLUE}[*] Installing Reverse Engineering Tools...${NC}"

# radare2
if [ ! -d "/opt/radare2" ]; then
    git clone https://github.com/radareorg/radare2 /opt/radare2 2>/dev/null
    cd /opt/radare2 && sys/install.sh 2>/dev/null
    echo -e "${GREEN}  ✓ radare2${NC}"
else
    echo -e "${YELLOW}  ~ radare2 already installed${NC}"
fi

# binwalk
apt install -y binwalk 2>/dev/null
echo -e "${GREEN}  ✓ binwalk${NC}"

# strings (part of binutils)
echo -e "${GREEN}  ✓ strings${NC}"

# objdump (part of binutils)
echo -e "${GREEN}  ✓ objdump${NC}"

# apktool
if [ ! -f "/usr/local/bin/apktool" ]; then
    wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool 2>/dev/null
    wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O /usr/local/bin/apktool.jar 2>/dev/null
    chmod +x /usr/local/bin/apktool
    echo -e "${GREEN}  ✓ apktool${NC}"
else
    echo -e "${YELLOW}  ~ apktool already installed${NC}"
fi

# ========================================
# CRYPTOGRAPHY
# ========================================
echo -e "${BLUE}[*] Installing Cryptography Tools...${NC}"

# hashcat
apt install -y hashcat 2>/dev/null
echo -e "${GREEN}  ✓ hashcat${NC}"

# John the Ripper
apt install -y john 2>/dev/null
echo -e "${GREEN}  ✓ john${NC}"

# hash-identifier
pip3 install hash-identifier 2>/dev/null || echo -e "${RED}  ✗ hash-identifier (skipped)${NC}"

# RsaCtfTool
if [ ! -d "/opt/RsaCtfTool" ]; then
    git clone https://github.com/RsaCtfTool/RsaCtfTool.git /opt/RsaCtfTool 2>/dev/null
    pip3 install -r /opt/RsaCtfTool/requirements.txt 2>/dev/null
    ln -sf /opt/RsaCtfTool/RsaCtfTool.py /usr/local/bin/rsactftool 2>/dev/null
    echo -e "${GREEN}  ✓ RsaCtfTool${NC}"
else
    echo -e "${YELLOW}  ~ RsaCtfTool already installed${NC}"
fi

# ========================================
# FORENSICS
# ========================================
echo -e "${BLUE}[*] Installing Forensics Tools...${NC}"

# Wireshark (CLI)
apt install -y tshark 2>/dev/null
echo -e "${GREEN}  ✓ tshark${NC}"

# tcpdump
apt install -y tcpdump 2>/dev/null
echo -e "${GREEN}  ✓ tcpdump${NC}"

# foremost
apt install -y foremost 2>/dev/null
echo -e "${GREEN}  ✓ foremost${NC}"

# scalpel
apt install -y scalpel 2>/dev/null
echo -e "${GREEN}  ✓ scalpel${NC}"

# exiftool
apt install -y exiftool 2>/dev/null
echo -e "${GREEN}  ✓ exiftool${NC}"

# volatility
pip3 install volatility3 2>/dev/null
echo -e "${GREEN}  ✓ volatility3${NC}"

# bulk_extractor
apt install -y bulk-extractor 2>/dev/null || echo -e "${RED}  ✗ bulk_extractor (skipped)${NC}"

# ========================================
# STEGANOGRAPHY
# ========================================
echo -e "${BLUE}[*] Installing Steganography Tools...${NC}"

# steghide
apt install -y steghide 2>/dev/null
echo -e "${GREEN}  ✓ steghide${NC}"

# stegcracker
pip3 install stegcracker 2>/dev/null
echo -e "${GREEN}  ✓ stegcracker${NC}"

# zsteg
gem install zsteg 2>/dev/null
echo -e "${GREEN}  ✓ zsteg${NC}"

# stegseek
if ! command -v stegseek &> /dev/null; then
    wget https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb -O /tmp/stegseek.deb 2>/dev/null
    dpkg -i /tmp/stegseek.deb 2>/dev/null || apt install -f -y 2>/dev/null
    rm /tmp/stegseek.deb 2>/dev/null
    echo -e "${GREEN}  ✓ stegseek${NC}"
else
    echo -e "${YELLOW}  ~ stegseek already installed${NC}"
fi

# ========================================
# PASSWORD CRACKING
# ========================================
echo -e "${BLUE}[*] Installing Password Cracking Tools...${NC}"

# hydra
apt install -y hydra 2>/dev/null
echo -e "${GREEN}  ✓ hydra${NC}"

# medusa
apt install -y medusa 2>/dev/null || echo -e "${RED}  ✗ medusa (skipped)${NC}"

# fcrackzip
apt install -y fcrackzip 2>/dev/null
echo -e "${GREEN}  ✓ fcrackzip${NC}"

# ========================================
# PRIVILEGE ESCALATION
# ========================================
echo -e "${BLUE}[*] Installing Privilege Escalation Tools...${NC}"

# LinPEAS
if [ ! -f "/usr/local/bin/linpeas.sh" ]; then
    wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O /usr/local/bin/linpeas.sh 2>/dev/null
    chmod +x /usr/local/bin/linpeas.sh
    echo -e "${GREEN}  ✓ LinPEAS${NC}"
else
    echo -e "${YELLOW}  ~ LinPEAS already installed${NC}"
fi

# pspy
if [ ! -f "/usr/local/bin/pspy64" ]; then
    wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -O /usr/local/bin/pspy64 2>/dev/null
    chmod +x /usr/local/bin/pspy64
    echo -e "${GREEN}  ✓ pspy${NC}"
else
    echo -e "${YELLOW}  ~ pspy already installed${NC}"
fi

# ========================================
# EXPLOITATION FRAMEWORKS
# ========================================
echo -e "${BLUE}[*] Installing Exploitation Frameworks...${NC}"

# Metasploit (Optional - Large install)
read -p "Install Metasploit Framework? (Large download) [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
    chmod +x /tmp/msfinstall
    /tmp/msfinstall
    echo -e "${GREEN}  ✓ Metasploit${NC}"
else
    echo -e "${YELLOW}  ~ Metasploit skipped${NC}"
fi

# ========================================
# MISCELLANEOUS TOOLS
# ========================================
echo -e "${BLUE}[*] Installing Miscellaneous Tools...${NC}"

# searchsploit
if [ ! -d "/opt/exploitdb" ]; then
    git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb 2>/dev/null
    ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
    echo -e "${GREEN}  ✓ searchsploit${NC}"
else
    echo -e "${YELLOW}  ~ searchsploit already installed${NC}"
fi

# jq (JSON processor)
apt install -y jq 2>/dev/null
echo -e "${GREEN}  ✓ jq${NC}"

# xxd (hex dump)
echo -e "${GREEN}  ✓ xxd${NC}"

# base64
echo -e "${GREEN}  ✓ base64${NC}"

# ========================================
# PYTHON LIBRARIES
# ========================================
echo -e "${BLUE}[*] Installing Python Libraries...${NC}"

pip3 install --upgrade \
    requests \
    beautifulsoup4 \
    pycryptodome \
    z3-solver \
    angr \
    capstone \
    keystone-engine \
    unicorn \
    scapy \
    2>/dev/null

echo -e "${GREEN}  ✓ Python libraries installed${NC}"

# ========================================
# CLEANUP
# ========================================
echo -e "${YELLOW}[*] Cleaning up...${NC}"
apt autoremove -y 2>/dev/null
apt clean 2>/dev/null

# ========================================
# FINAL MESSAGE
# ========================================
echo -e "\n${GREEN}"
cat << "EOF"
  ___           _        _ _       _   _             
 |_ _|_ __  ___| |_ __ _| | | __ _| |_(_) ___  _ __  
  | || '_ \/ __| __/ _` | | |/ _` | __| |/ _ \| '_ \ 
  | || | | \__ \ || (_| | | | (_| | |_| | (_) | | | |
 |___|_| |_|___/\__\__,_|_|_|\__,_|\__|_|\___/|_| |_|
                                                      
   ____                      _      _       _ 
  / ___|___  _ __ ___  _ __ | | ___| |_ ___| |
 | |   / _ \| '_ ` _ \| '_ \| |/ _ \ __/ _ \ |
 | |__| (_) | | | | | | |_) | |  __/ ||  __/_|
  \____\___/|_| |_| |_| .__/|_|\___|\__\___(_)
                      |_|                      
EOF
echo -e "${NC}"

echo -e "${GREEN}[✓] CTF Tools installation complete!${NC}\n"
echo -e "${BLUE}Installed tools are ready to use. Happy hacking!${NC}\n"
echo -e "${YELLOW}Note: Some tools may require additional configuration.${NC}"
echo -e "${YELLOW}PATH updates: You may need to restart your terminal or run: source ~/.bashrc${NC}\n"

# Add Go bin to PATH if not already there
if ! grep -q 'export PATH=$PATH:$HOME/go/bin' "$HOME/.bashrc"; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> "$HOME/.bashrc"
    echo -e "${GREEN}[+] Added Go bin to PATH in .bashrc${NC}"
fi

echo -e "${BLUE}Enjoy your CTF adventures! 🚀${NC}\n"
