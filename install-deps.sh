#!/bin/bash
# atarus-recon dependency installer
# Downloads prebuilt binaries from GitHub releases (no Go required)

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "atarus-recon dependency installer"
echo "================================="
echo ""

# Detect OS and architecture
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS="unknown"
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64) PD_ARCH="amd64"; GOWITNESS_ARCH="amd64" ;;
    aarch64|arm64) PD_ARCH="arm64"; GOWITNESS_ARCH="arm64" ;;
    armv7l) PD_ARCH="arm"; GOWITNESS_ARCH="arm" ;;
    *) PD_ARCH="amd64"; GOWITNESS_ARCH="amd64" ;;
esac

PLATFORM="linux"
echo -e "${GREEN}Detected OS:${NC} $OS"
echo -e "${GREEN}Architecture:${NC} $ARCH (downloading $PLATFORM-$PD_ARCH binaries)"
echo ""

# DNS sanity check (catches the VM-with-broken-DNS case)
if ! getent hosts api.github.com >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] DNS lookup for api.github.com failed.${NC}"
    echo "    If you're on a VM and DNS is unreliable, add public resolvers:"
    echo "      sudo bash -c 'echo \"nameserver 1.1.1.1\" > /etc/resolv.conf'"
    echo "      sudo bash -c 'echo \"nameserver 8.8.8.8\" >> /etc/resolv.conf'"
    echo ""
    echo "    Then re-run this script."
    exit 1
fi

mkdir -p "$HOME/go/bin"
GOBIN_PATH="$HOME/go/bin"

if [[ ":$PATH:" != *":$GOBIN_PATH:"* ]]; then
    export PATH="$PATH:$GOBIN_PATH"
fi

echo "Installing system tools (nmap, whois, unzip)..."
case "$OS" in
    kali|debian|ubuntu)
        sudo apt-get update -qq 2>&1 | tail -2
        sudo apt-get install -y nmap whois unzip 2>&1 | grep -v "is already the newest" | tail -3
        ;;
    arch)
        sudo pacman -Sy --noconfirm nmap whois unzip
        ;;
    fedora|rhel|centos)
        sudo dnf install -y nmap whois unzip
        ;;
    *)
        echo -e "${YELLOW}[!] Unknown OS. Install nmap, whois, unzip manually.${NC}"
        ;;
esac
echo ""

install_from_github() {
    local name=$1
    local repo=$2
    local pattern=$3
    local archive_type=$4

    echo "Installing $name..."

    if [ -f "$HOME/go/bin/$name" ]; then
        echo -e "${YELLOW}    [*] $name already exists, skipping${NC}"
        return
    fi

    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local download_url=$(curl -s "$api_url" | grep "browser_download_url.*$pattern" | head -1 | cut -d'"' -f4)

    if [ -z "$download_url" ]; then
        echo -e "${RED}    [!] Could not find release matching '$pattern' for $repo${NC}"
        return
    fi

    echo "    Downloading: $download_url"

    cd /tmp
    local filename=$(basename "$download_url")
    rm -f "$filename"

    if ! curl -sL -o "$filename" "$download_url"; then
        echo -e "${RED}    [!] Download failed${NC}"
        return
    fi

    if [ "$archive_type" = "zip" ]; then
        rm -rf "/tmp/${name}-extract"
        unzip -o "$filename" -d "/tmp/${name}-extract" > /dev/null
        find "/tmp/${name}-extract" -type f -name "$name" -executable -exec mv {} "$HOME/go/bin/$name" \;
        rm -rf "/tmp/${name}-extract"
    elif [ "$archive_type" = "tar.gz" ]; then
        tar -xzf "$filename" -C /tmp/
        find /tmp -maxdepth 2 -type f -name "$name" -newer "$filename" -exec mv {} "$HOME/go/bin/$name" \;
    fi

    rm -f "$filename"

    if [ -f "$HOME/go/bin/$name" ]; then
        chmod +x "$HOME/go/bin/$name"
        echo -e "${GREEN}    [+] $name installed${NC}"
    else
        echo -e "${RED}    [!] $name extraction failed${NC}"
    fi
    echo ""
}

install_from_github "subfinder" "projectdiscovery/subfinder" "subfinder_.*_${PLATFORM}_${PD_ARCH}\.zip" "zip"
install_from_github "httpx" "projectdiscovery/httpx" "httpx_.*_${PLATFORM}_${PD_ARCH}\.zip" "zip"
install_from_github "nuclei" "projectdiscovery/nuclei" "nuclei_.*_${PLATFORM}_${PD_ARCH}\.zip" "zip"

if [ ! -f "$HOME/go/bin/gowitness" ]; then
    echo "Installing gowitness (raw binary)..."
    GW_URL=$(curl -s "https://api.github.com/repos/sensepost/gowitness/releases/latest" | grep "browser_download_url" | grep "${PLATFORM}-${GOWITNESS_ARCH}" | grep -v "\.sha256" | head -1 | cut -d'"' -f4)

    if [ -n "$GW_URL" ]; then
        curl -sL -o "$HOME/go/bin/gowitness" "$GW_URL"
        chmod +x "$HOME/go/bin/gowitness"
        echo -e "${GREEN}    [+] gowitness installed${NC}"
    else
        echo -e "${RED}    [!] Could not find gowitness release${NC}"
    fi
    echo ""
fi

if [ -f "$HOME/go/bin/nuclei" ]; then
    echo "Updating nuclei templates..."
    "$HOME/go/bin/nuclei" -update-templates 2>&1 | tail -3
    echo ""
fi

echo "================================="
echo "Verification"
echo "================================="
ALL_OK=true
for tool in subfinder httpx nuclei gowitness; do
    if [ -f "$HOME/go/bin/$tool" ]; then
        echo -e "  ${GREEN}[+] $tool${NC}"
    else
        echo -e "  ${RED}[!] $tool not found${NC}"
        ALL_OK=false
    fi
done

for tool in nmap whois; do
    if command -v "$tool" &> /dev/null; then
        echo -e "  ${GREEN}[+] $tool${NC}"
    else
        echo -e "  ${RED}[!] $tool not found${NC}"
        ALL_OK=false
    fi
done

echo ""
echo -e "${YELLOW}IMPORTANT:${NC} Add ~/go/bin to your PATH permanently."
echo "    Add this line to ~/.bashrc or ~/.zshrc:"
echo "      export PATH=\"\$PATH:\$HOME/go/bin\""
echo ""

if [ "$ALL_OK" = true ]; then
    echo -e "${GREEN}All dependencies installed.${NC}"
else
    echo -e "${YELLOW}Some tools failed. Check output above.${NC}"
fi

echo ""
echo "Run a full scan:"
echo "  source venv/bin/activate"
echo "  atarus-recon -t example.com --format all -v"
