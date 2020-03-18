#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Run this script as root. Exiting."
  exit 0
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
LIGHT_BLUE='\033[1;34m'

installdotfiles() {
  if [[ ! -e /root/.dotfiles ]]; then
    echo -e "${GREEN}[+] installing dotfiles${NC}"
    git clone https://github.com/mattzajork/dotfiles.git /root/.dotfiles
    cd /root/.dotfiles && ./install
  else
    echo -e "${LIGHT_BLUE}[=] dotfiles already installed, skipping${NC}"
  fi
}

installdirsearch() {
  if [[ ! -e /usr/local/bin/dirsearch ]]; then
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

installgithubrepos() {
  github_repos=(
    'BloodHoundAD/BloodHound'
    'Ganapati/RsaCtfTool'
    'Greenwolf/social_mapper'
    'Hackplayers/evil-winrm'
    'IOActive/jdwp-shellifier'
    'PowerShellMafia/PowerSploit'
    'SecWiki/windows-kernel-exploits'
    'SecureAuthCorp/impacket'
    'bitsadmin/wesng'
    'danielmiessler/SecLists'
    'flozz/p0wny-shell'
    'maurosoria/dirsearch'
    'mthbernardes/rsg'
    'pwntester/ysoserial.net'
    'rasta-mouse/Sherlock'
    'rebootuser/LinEnum'
    'samratashok/nishang'
    'swisskyrepo/PayloadsAllTheThings'
    'carlospolop/privilege-escalation-awesome-scripts-suite'
    'fox-it/mitm6'
    'blechschmidt/massdns'
    'FortyNorthSecurity/EyeWitness'
    'assetnote/commonspeak2-wordlists'
    'ProjectAnte/dnsgen'
    'Abss0x7tbh/bass'
  )
  echo -e "${LIGHT_BLUE}Checking GitHub Repos... ${NC}"
  for i in ${github_repos[@]}; do
    [[ $i =~ /([\.a-zA-Z0-9_\-]+)$ ]]
    dir=${BASH_REMATCH[1]}
    echo -e "${GREEN}[+] checking repository $dir${NC}"
    if [[ -e "/opt/$dir" ]]; then 
      cd /opt/$dir && git pull; 
    else 
      cd /opt && git clone "https://github.com/$i.git"; 
    fi
  done
}

installaptpackages() {
  echo -e "${GREEN}[+] installing apt packages${NC}"
  apt install -y clamav dialog hping3 ipcalc macchanger p7zip python-pip python3-pip silversearcher-ag \
    strace tree vim vlc xclip xfonts-terminus rlwrap imagemagick default-jdk cmake forensics-extra gdb edb-debugger gdbserver
}

removeunusedpackages() {
  echo -e "${YELLOW}[-] removing unused packages${NC}"
  apt -y autoremove
}

getchisel() {
  chisel_version='1.3.1'
  if [[ ! -d /opt/chisel ]]; then
    echo -e "${GREEN}[+] installing chisel${NC}"
    mkdir /opt/chisel
  else
    echo -e "${LIGHT_BLUE}[=] chisel already installed, skipping${NC}"
  fi

  for arch in linux_amd64 linux_386 windows_amd64.exe windows_386.exe; do
    if [[ ! -e "/opt/chisel/chisel_${arch}" ]]; then
      wget https://github.com/jpillora/chisel/releases/download/$chisel_version/chisel_$arch.gz -O /opt/chisel/chisel_$arch.gz
      gunzip /opt/chisel/chisel_$arch.gz
      chmod +x /opt/chisel/chisel_$arch
    fi
  done
}

installamass() {
  if [[ ! -e /usr/local/bin/amass ]]; then
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
  if [[ ! -e /usr/local/bin/aquatone ]]; then
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
  netcat_win_file=netcat-win32-1.12.zip
  if [[ ! -d /opt/netcat-win ]]; then
    mkdir -p /opt/netcat-win
  fi
  if [[ ! -e /opt/netcat-win/nc64.exe ]]; then
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
  if [[ ! -d $dir ]]; then
    echo -e "${GREEN}[+] creating directory $dir${NC}"
  fi
  if [[ ! -e /opt/ghidra/ghidraRun ]]; then
    echo -e "${GREEN}[+] installing ghidra${NC}"
    wget https://ghidra-sre.org/https://ghidra-sre.org/ghidra_9.1.2_PUBLIC_20200212.zip -O /opt/ghidra.zip
  else
    echo -e "${LIGHT_BLUE}[=] ghidra already installed, skipping${NC}"
  fi
}

downloadida() {
  if [[ ! -e /root/idafree70_linux.run ]]; then
    echo -e "${GREEN}[+] downloading ida${NC}"
    wget https://out7.hex-rays.com/files/idafree70_linux.run  -O ~/root/Downloads/idafree70_linux.run
    echo -e "${BLUE}[!] run ida installer manually${NC}"
  else
    echo -e "${LIGHT_BLUE}[=] ida already downloaded, skipping${NC}"
  fi
}

installpythonpackages() {
  echo -e "${GREEN}[+] installing python packages${NC}"
  pip3 install --quiet protonvpn-cli
  pip3 install --quiet pwntools
  pip install --quiet pwntools
}

getpspy() {
  dir=/opt/pspy
  if [[ ! -d $dir ]]; then
    echo -e "${GREEN}[+] creating directory $dir${NC}"
    mkdir "$dir"
  fi
  if [[ ! -e /opt/pspy64 ]]; then
    echo -e "${GREEN}[+] downloading pspy64${NC}"
    wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -O /opt/pspy64
  else
    echo -e "${LIGHT_BLUE}[=] pspy64 already downloaded${NC}"
  fi
  if [[ ! -e /opt/pspy32 ]]; then
    echo -e "${GREEN}[+] downloading pspy32${NC}"
    wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O /opt/pspy32
  else
    echo -e "${LIGHT_BLUE}[=] pspy32 already downloaded${NC}"
  fi
}

allowrootvlc() {
  sed -i 's/geteuid/getppid/' /usr/bin/vlc
}

installscripts() {
  cp $DIR/files/scripts/scan.sh /opt/scan.sh
  chmod +x /opt/scan.sh
}

getjhaddixlists() {
  if [[ ! -e /opt/dns-all.txt ]]; then
    echo -e "${GREEN}[+] installing dns-all.txt${NC}"
    wget https://gist.githubusercontent.com/mattzajork/19c8ec7fadc02e91f0d03fdc878a0352/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt -O /opt/dns-all.txt
  fi
  if [[ ! -e /opt/cloud-metadata.txt ]]; then
    echo -e "${GREEN}[+] installing cloud-metadata.txt${NC}"
    wget https://gist.github.com/mattzajork/25aec3fda2f8f1858862cbfbc148add2/raw/a4869d58a5ce337d1465c2d1b29777b9eecd371f/cloud_metadata.txt -O /opt/cloud-metadata.txt
  fi
  if [[ ! -e /opt/content-all.txt ]]; then
    echo -e "${GREEN}[+] installing content-all.txt${NC}"
    wget https://gist.github.com/mattzajork/d43d8b2a1f7ec56237e13cfc9f247cbe/raw/c81a34fe84731430741e0463eb6076129c20c4c0/content_discovery_all.txt -O /opt/content-all.txt
  fi
}

getjythonstandalone() {
  if [[ ! -e /opt/jython-standalone.jar ]]; then
    echo -e "${GREEN}[+] installing jython-standalone${NC}"
    wget http://search.maven.org/remotecontent?filepath=org/python/jython-standalone/2.7.1/jython-standalone-2.7.1.jar -O /opt/jython-standalone.jar
  else
    echo -e "${LIGHT_BLUE}[=] jython-standalone already installed, skipping${NC}"
  fi
}

buildandinstallmassdns() {
  if [[ ! -e /usr/local/bin/massdns ]]; then
    echo -e "${GREEN}[+] installing massdns${NC}"
    cd /opt/massdns/
    make
    make install
    cd "$DIR"
  else
    echo -e "${LIGHT_BLUE}[=] massdns already installed, skipping${NC}"
  fi
}

installgo() {
  if [[ -d /usr/local/go ]]; then
    echo -e "${LIGHT_BLUE}[=] go already installed, skipping${NC}"
  else
    echo -e "${GREEN}[+] installing go${NC}"
    wget https://dl.google.com/go/go1.14.linux-amd64.tar.gz -O /tmp/golang.tar.gz
    tar -C /usr/local -xzf /tmp/golang.tar.gz
    rm /tmp/golang.tar.gz
    mkdir /root/go-workspace
  fi
}

installwaybackurls() {
  if [[ -e $(which waybackurls) ]]; then
    echo -e "${LIGHT_BLUE}[=] waybackurls already installed, skipping${NC}"
  else
    echo -e "${GREEN}[+] installing waybackurls${NC}"
    go get github.com/tomnomnom/waybackurls
  fi
}

installffuf() {
  if [[ -e $(which ffuf) ]]; then
    echo -e "${LIGHT_BLUE}[=] ffuf already installed, skipping${NC}"
  else
    echo -e "${GREEN}[+] installing ffuf${NC}"
    go get github.com/ffuf/ffuf
  fi
}

removeunusedpackages
installaptpackages
installdotfiles
installdirsearch
installaquatone
installamass
installgo
getchisel
getpspy
installwinnc
getjythonstandalone
getjhaddixlists
installwaybackurls
installffuf
buildandinstallmassdns
installgithubrepos
installpythonpackages
allowrootvlc
installscripts
