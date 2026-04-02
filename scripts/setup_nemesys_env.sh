#!/usr/bin/env bash
set -euo pipefail

NEMESYS_HOME="${NEMESYS_HOME:-/root/tools/nemesys}"
NEMESYS_REPO_URL="${NEMESYS_REPO_URL:-https://github.com/vs-uulm/nemesys.git}"
NEMESYS_VENV="${NEMESYS_VENV:-/root/venv_nemesys}"
NEMESYS_PYTHON="${NEMESYS_PYTHON:-python3}"
NEMESYS_INSTALL_NETZOB_NEXT="${NEMESYS_INSTALL_NETZOB_NEXT:-false}"

echo "[1/6] Ensure NEMESYS repository exists: ${NEMESYS_HOME}"
if [ ! -d "${NEMESYS_HOME}" ]; then
  mkdir -p "$(dirname "${NEMESYS_HOME}")"
  git clone --depth 1 "${NEMESYS_REPO_URL}" "${NEMESYS_HOME}"
else
  echo "      Reuse existing repo."
fi

if ! command -v "${NEMESYS_PYTHON}" >/dev/null 2>&1; then
  echo "Python interpreter not found: ${NEMESYS_PYTHON}" >&2
  exit 2
fi

echo "[2/6] Create virtual environment: ${NEMESYS_VENV}"
"${NEMESYS_PYTHON}" -m venv "${NEMESYS_VENV}"

echo "[3/6] Upgrade pip toolchain"
"${NEMESYS_VENV}/bin/python" -m pip install --upgrade pip setuptools wheel

if command -v apt-get >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
  echo "[4/6] Install system packages for pcapy/scipy build"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y libpcap-dev libpq-dev build-essential
else
  echo "[4/6] Skip apt install (need libpcap-dev/libpq-dev/build-essential manually if build fails)"
fi

echo "[5/6] Install NEMESYS Python dependencies"
"${NEMESYS_VENV}/bin/pip" install -r "${NEMESYS_HOME}/requirements.txt"

if [ "${NEMESYS_INSTALL_NETZOB_NEXT}" = "true" ]; then
  echo "      Install Netzob next branch (optional)"
  TMP_NETZOB_DIR="$(mktemp -d)"
  git clone --depth 1 --single-branch -b next https://github.com/netzob/netzob.git "${TMP_NETZOB_DIR}"
  "${NEMESYS_VENV}/bin/pip" install "${TMP_NETZOB_DIR}/src/netzob"
fi

echo "[6/6] Done"
echo "Add/confirm these .env lines:"
echo "NEMESYS_PYTHON_BIN=${NEMESYS_VENV}/bin/python"
echo "NEMESYS_HOME=${NEMESYS_HOME}"
echo "NEMESYS_MODE=auto"
