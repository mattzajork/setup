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
  apt install -y ipcalc tmux p7zip-full python-pip python3-pip htop ripgrep tree vim rlwrap jq
}

removeunusedpackages() {
  echo -e "${YELLOW}[-] removing unused packages${NC}"
  apt -y autoremove
}

installbinaries() {
  cd /usr/local/bin/
  git clone https://github.com/mattzajork/bbbinaries.git ./
}

removeunusedpackages
installaptpackages
installdotfiles
installgithubrepos
installbinaries

echo 'export PATH=/usr/local/bin/bbbinaries:$PATH' > ~/.bashrc.local
nuclei -update-templates

tee /usr/local/bin/bbscan << EOF
#!/bin/bash
read -p "Enter the TLD: " TARGET 
amass enum -max-dns-queries 8000 -d \$TARGET -o /tmp/domains
cat /tmp/domains | httpx -silent -threads 200 -ports 80,81,443,4443,8009,8080,8081,8090,8180,8443 > /tmp/urls; 
nuclei -H "X-Security-Research: hackerone/bugcrowd" -l /tmp/urls -t /root/nuclei-templates/technologies/tech-detect.yaml
nuclei -H "X-Security-Research: hackerone/bugcrowd" -l /tmp/urls \$(grep -r "severity: low\|severity: medium" /root/nuclei-templates | awk -F':' '{print "-t " \$1 " "}' | tr -d '\n')
echo "scan \$(wc -l /tmp/urls) URLs complete"
EOF

chmod +x /usr/local/bin/bbscan
