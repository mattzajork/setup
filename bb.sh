#!/bin/bash
# setup script for bb
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

installgithubrepos() {
  github_repos=(
    'danielmiessler/SecLists'
    'shmilylty/OneForAll'
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

installpipxpackages() {
  git_repos=(
    'https://github.com/fox-it/mitm6.git'
  )
  echo -e "${GREEN}[+] installing pipx packages $dir${NC}"
  for i in ${git_repos[@]}; do
    echo $i
  done
}

installaptpackages() {
  echo -e "${GREEN}[+] installing apt packages${NC}"
  apt install -y ipcalc p7zip-full python-pip python3-pip htop ripgrep tree vim rlwrap jq
}

removeunusedpackages() {
  echo -e "${YELLOW}[-] removing unused packages${NC}"
  apt -y autoremove
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

installbinaries() {
  cd /usr/local/bin/
  git clone https://github.com/mattzajork/bbbinaries.git ./
}

removeunusedpackages
installaptpackages
installdotfiles
installgithubrepos
getjhaddixlists
installbinaries

echo 'export PATH=/usr/local/bin/bbbinaries:$PATH' > ~/.bashrc.local
nuclei -update-templates
cd /opt/OneForAll && pip3 install -r requirements.txt

tee /usr/local/bin/bbscan << EOF
#!/bin/bash
read -p "Enter the TLD: " TARGET 
cd /opt/OneForAll
python3 oneforall.py --target \$TARGET run
cat results/\$TARGET.csv | cut -d ',' -f6 | httpx -silent -threads 200 -ports 80,81,443,4443,8009,8080,8081,8090,8180,8443 > /tmp/urls; 
nuclei -H "X-HackerOne-Research: hackerone" -l /tmp/urls -t /root/nuclei-templates/technologies/tech-detect.yaml
nuclei -H "X-HackerOne-Research: hackerone" -l /tmp/urls \$(grep -r "severity: low\|severity: medium" /root/nuclei-templates | awk -F':' '{print "-t " \$1 " "}' | tr -d '\n')
echo "scan \$(wc -l /tmp/urls) URLs complete"
EOF

chmod +x /usr/local/bin/bbscan
