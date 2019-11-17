#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Run this script as root. Exiting."
  exit
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
LIGHT_BLUE='\033[1;34m'

checkfile() {
  if [ -f $1 ]; then
    return 1
  else
    return 0 
  fi
}

checkdirectory() {
  if [ -d $1 ]; then
    return 1 
  else
    return 0 
  fi
}

installdotfiles() {
  checkdirectory "/root/.dotfiles"
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] installing dotfiles${NC}"
    git clone https://github.com/mattzajork/dotfiles.git /root/.dotfiles
    cd /root/.dotfiles && ./install
  else
    echo -e "${LIGHT_BLUE}[=] dotfiles already installed, skipping${NC}"
  fi
}

installdirsearch() {
  checkfile "/usr/local/bin/dirsearch"
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] installing dirsearch${NC}"
    cat > /usr/local/bin/dirsearch <<EOF
#!/bin/bash
cd /opt/dirsearch
python3 dirsearch.py \$@
EOF
    chmod +x /usr/local/bin/dirsearch
  else
    echo -e "${LIGHT_BLUE}[=] dirsearch already installed, skipping${NC}"
  fi
}

installprotonvpn() {
  checkfile "/usr/local/bin/protonvpn-cli"
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] installing protonvpn${NC}"
    wget https://raw.githubusercontent.com/ProtonVPN/protonvpn-cli/master/protonvpn-cli.sh -O /tmp/protonvpn-cli.sh
    chmod +x /tmp/protonvpn-cli.sh
    /tmp/protonvpn-cli.sh --install
    rm /tmp/protonvpn-cli.sh
  else
    echo -e "${LIGHT_BLUE}[=] protonvpn already installed, skipping${NC}"
  fi
}

installgithubrepos() {
  github_repos=(
    'BloodHoundAD/BloodHound'
    'Ganapati/RsaCtfTool'
    'Greenwolf/social_mapper'
    'Hackplayers/evil-winrm'
    'PowerShellMafia/PowerSploit'
    'SecWiki/windows-kernel-exploits'
    'SecureAuthCorp/impacket'
    'bitsadmin/wesng'
    'danielmiessler/SecLists'
    'flozz/p0wny-shell'
    'maurosoria/dirsearch'
    'pwntester/ysoserial.net'
    'rasta-mouse/Sherlock'
    'rebootuser/LinEnum'
    'samratashok/nishang'
    'sensepost/reGeorg'
    'swisskyrepo/PayloadsAllTheThings'
  )
  echo -e "${LIGHT_BLUE}Checking GitHub Repos... ${NC}"
  for i in ${github_repos[@]}; do
    [[ $i =~ /([\.a-zA-Z0-9_\-]+)$ ]]
    dir=${BASH_REMATCH[1]}
    echo -e "${GREEN}[+] checking repository $dir${NC}"
    checkdirectory "/opt/$dir"
    if [[ $? == 1 ]]; then 
      cd /opt/$dir && git pull; 
    else 
      cd /opt && git clone "https://github.com/$i.git"; 
    fi
  done
}

installaptpackages() {
  echo -e "${GREEN}[+] installing apt packages${NC}"
  apt install -y clamav dialog hping3 ipcalc macchanger p7zip python-pip python3-pip silversearcher-ag \
    strace tree vim vlc xclip xfonts-terminus rlwrap imagemagick default-jdk cmake forensics-extra gdb edb-debugger gdbserver jython
}

removeunusedpackages() {
  echo -e "${YELLOW}[-] removing unused packages${NC}"
  apt -y autoremove
}

getchisel() {
  echo -e "${GREEN}[+] installing chisel${NC}"
  chisel_version='1.3.1'
  checkdirectory "/opt/chisel"
  if [[ $? == 0 ]]; then
    mkdir /opt/chisel
  fi

  for arch in linux_amd64 linux_386 windows_amd64.exe windows_386.exe; do
    checkfile "/opt/chisel/chisel_${arch}"
    if [[ $? == 0 ]]; then
      wget https://github.com/jpillora/chisel/releases/download/$chisel_version/chisel_$arch.gz -O /opt/chisel/chisel_$arch.gz
      gunzip /opt/chisel/chisel_$arch.gz
      chmod +x /opt/chisel/chisel_$arch
    fi
  done
}

installamass() {
  checkfile "/usr/local/bin/amass"
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] installing amass${NC}"
    amass_version=3.1.10
    amass_file="amass_v${amass_version}_linux_amd64.zip"
    wget https://github.com/OWASP/Amass/releases/download/v$amass_version/$amass_file -O /tmp/$amass_file
    cd /tmp && unzip -u $amass_file
    mv /tmp/amass_v*/amass /usr/local/bin
    rm -rf amass*
  else
    echo -e "${LIGHT_BLUE}[=] amass already installed, skipping${NC}"
  fi
}

installaquatone() {
  checkfile "/usr/local/bin/aquatone"
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] installing aquatone${NC}"
    aquatone_version=1.7.0
    aquatone_file=aquatone_linux_amd64
    wget "https://github.com/michenriksen/aquatone/releases/download/v${aquatone_version}/${aquatone_file}_${aquatone_version}.zip" -O /tmp/$aquatone_file.zip
    cd /tmp && unzip -u $aquatone_file.zip
    mv /tmp/aquatone /usr/local/bin
    rm -rf /tmp/aquatone* /tmp/README.md /tmp/LICENSE.txt
  else
    echo -e "${LIGHT_BLUE}[=] aquatone already installed, skipping${NC}"
  fi
}

installwinnc() {
  checkdirectory "/opt/netcat-win"
  netcat_win_file=netcat-win32-1.12.zip
  if [[ $? == 0 ]]; then
    mkdir -p /opt/netcat-win
  fi
  checkfile "/opt/netcat-win/nc64.exe"
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] installing win netcat${NC}"
    wget https://eternallybored.org/misc/netcat/$netcat_win_file -O /opt/netcat-win/$netcat_win_file
    cd /opt/netcat-win && unzip $netcat_win_file
    rm /opt/netcat-win/$netcat_win_file
  else
    echo -e "${LIGHT_BLUE}[=] win netcat already installed, skipping${NC}"
  fi
}

installghidra() {
  dir=/opt/ghidra
  checkdirectory "$dir"
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] creating directory $dir${NC}"
  fi
  checkfile "/opt/ghidra/ghidraRun"
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] installing ghidra${NC}"
    wget https://ghidra-sre.org/ghidra_9.1-BETA_DEV_20190923.zip -O /opt/ghidra.zip
  else
    echo -e "${LIGHT_BLUE}[=] ghidra already installed, skipping${NC}"
  fi
}

downloadida() {
  checkfile "/root/idafree70_linux.run"
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] downloading ida${NC}"
    wget https://out7.hex-rays.com/files/idafree70_linux.run  -O ~/root/Downloads/idafree70_linux.run
    echo -e "${BLUE}[!] run ida installer manually${NC}"
  else
    echo -e "${LIGHT_BLUE}[=] ida already downloaded, skipping${NC}"
  fi
}

installpythonpackages() {
  echo -e "${GREEN}[+] installing python packages${NC}"
  pip3 install pwntools
}

getpspy() {
  dir=/opt/pspy
  checkdirectory "$dir"
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] creating directory $dir${NC}"
    mkdir "$dir"
  fi
  checkfile "/opt/pspy64"
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] downloading pspy64${NC}"
    wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -O /opt/pspy64
  else
    echo -e "${LIGHT_BLUE}[=] pspy64 already downloaded${NC}"
  fi
  checkfile "/opt/pspy32"
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] downloading pspy64${NC}"
    wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O /opt/pspy32
  else
    echo -e "${LIGHT_BLUE}[=] pspy32 already downloaded${NC}"
  fi
}

installshell() {
  checkdirectory "/opt/..."
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] creating directory ...${NC}"
  fi
  checkfile "/bin/bash"
  if [[ $? == 0 ]]; then
    echo -e "${GREEN}[+] installing ...${NC}"
  else
    echo -e "${LIGHT_BLUE}[=] ... already installed, skipping${NC}"
  fi
}

removeunusedpackages
installaptpackages
installdotfiles
installdirsearch
installprotonvpn
installaquatone
installamass
getchisel
getpspy
installwinnc
installgithubrepos
installpythonpackages
