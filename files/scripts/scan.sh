#!/bin/bash
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
LIGHT_BLUE='\033[1;34m'

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
WORKDIR="$(pwd)"

echo -e "${LIGHT_BLUE}[*] detected working directory as: $WORKDIR${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] run this script as root. exiting.${NC}"
  exit 0
fi

# todo: check for arguments vs targets file
#if [ $# -eq 0 ]; then
#  echo -e "${RED}[!] no arguments supplied, exiting${NC}"
#fi

if [[ -d $WORKDIR/nmap ]]; then
  echo -e "${LIGHT_BLUE}[*] found existing nmap directory${NC}"
else
  echo -e "${GREEN}[+] creating nmap directory for output${NC}"
  mkdir "$WORKDIR/nmap"
fi

nmap_dir="$WORKDIR/nmap"

cleannmapdir() {
  echo -e "${GREEN}[+] cleaning nmap directory${NC}"
  rm -r $nmap_dir/*
}

scantoptcpports() {
  echo -e "${GREEN}[+] scanning top tcp ports${NC}"
  nmap -v -n --open -oX $nmap_dir/top-tcp-all-targets.xml --webxml -oG $nmap_dir/top-tcp-all-targets -iL ./targets
}

scantopudpports() {
  echo -e "${GREEN}[+] scanning top udp ports${NC}"
  nmap -v -n --open -sU -oX $nmap_dir/top-udp-all-targets.xml --webxml -oG $nmap_dir/top-udp-all-targets -iL ./targets
}

scanallopentcpports() {
  echo -e "${GREEN}[+] scanning all tcp ports${NC}"
  nmap -v -n --open -p- -oX $nmap_dir/all-tcp-all-targets.xml --webxml -oG $nmap_dir/all-tcp-all-targets -iL ./targets
}

targetedscan() {
  echo -e "${GREEN}[+] targeted scan${NC}"
  # targeted scans (svc discovery, default scripts) for each ip address from targets file
  while read LINE; do
    ports=$(grep $LINE $nmap_dir/all-tcp-all-targets | grep Ports | grep -oP '[0-9]+(?=/)' | tr '\n' ',' | sed '$s/,$//')
    nmap -v -n -Pn -sC -sV -oX $nmap_dir/$LINE-targeted.xml --webxml -oG $nmap_dir/$LINE-targeted -oN $nmap_dir/$LINE-targeted.nmap -p $ports $LINE
  done < ./targets
}

cleannmapdir
scantoptcpports
scantopudpports
scanallopentcpports
targetedscan
