#!/usr/bin/env bash
# ==============================================================================
# Aegis Invariant Kernel — Universal Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/Snehgabani/aegis-kernel/main/install.sh | sh
# ==============================================================================

set -e

RESET='\033[0m'
BOLD='\033[1m'
GREEN='\033[32m'
BLUE='\033[34m'
CYAN='\033[36m'
YELLOW='\033[33m'

echo -e "${CYAN}${BOLD}"
echo "  🛡️  AEGIS INVARIANT KERNEL INSTALLER"
echo "  Deterministic AI Agent Tool Clearance Gateway"
echo -e "${RESET}"

# 1. Detect Environment & Node.js
if command -v node >/dev/null 2>&1; then
  NODE_VER=$(node -v)
  echo -e "  ${GREEN}✓${RESET} Node.js detected: ${BOLD}${NODE_VER}${RESET}"
else
  echo -e "  ${YELLOW}!${RESET} Node.js not detected. You can also run Aegis in Python, Go, or Rust."
fi

# 2. Install @aegis-kernel/cli
echo -e "\n  ${BLUE}→${RESET} Installing ${BOLD}@aegis-kernel/cli${RESET} from npm..."
INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "${INSTALL_DIR}"
WRAPPER="${INSTALL_DIR}/aegis"

cat << 'INNER_EOF' > "${WRAPPER}"
#!/usr/bin/env bash
exec npx -y @aegis-kernel/cli "$@"
INNER_EOF
chmod +x "${WRAPPER}"
echo -e "  ${GREEN}✓${RESET} Installed standalone executable to: ${BOLD}${WRAPPER}${RESET}"

# Ensure in PATH
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
  echo -e "  ${YELLOW}!${RESET} Tip: Ensure ${BOLD}${INSTALL_DIR}${RESET} is in your PATH in ~/.bashrc or ~/.zshrc:"
  echo -e "    export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo -e "\n${GREEN}${BOLD}════════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  🎉 Aegis Invariant Kernel v1.0.0 is ready!${RESET}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════════${RESET}"
echo -e "\n  ${BOLD}Quick Start Commands:${RESET}"
echo -e "    ${CYAN}aegis init${RESET}           # Scaffold safety rules for your agent project"
echo -e "    ${CYAN}aegis scan ./${RESET}        # Scan codebase for hardcoded secrets & poisoned tools"
echo -e "    ${CYAN}aegis test${RESET}           # Run deterministic invariant test suite"
echo -e "    ${CYAN}aegis eval all${RESET}       # Benchmark against InjecAgent & AgentDojo"
echo -e "    ${CYAN}aegis verify-proof <dossier.json>${RESET}  # Verify cryptographic Merkle audit proof"
echo -e "\n  ${BOLD}Live Web Studio:${RESET} ${BLUE}https://snehgabani.github.io/aegis-kernel/playground.html${RESET}\n"
