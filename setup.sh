#!/usr/bin/env bash
# ==============================================================================
# CodeNova Internship Program • Batch 01 • Cybersecurity Track
# Task 1: Password Strength Checker (Credential Auditing & Entropy)
# Setup and Auto-Detection Script
# ==============================================================================

set -e

# ANSI Color Codes
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_DIM="\033[2m"
CLR_RED="\033[31m"
CLR_GREEN="\033[32m"
CLR_YELLOW="\033[33m"
CLR_BLUE="\033[34m"
CLR_MAGENTA="\033[35m"
CLR_CYAN="\033[36m"
CLR_WHITE="\033[37m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

print_banner() {
    echo -e "${CLR_CYAN}${CLR_BOLD}"
    echo "=========================================================================="
    echo "       CODENOVA CYBERSECURITY • TASK 1: CREDENTIAL AUDITING SUITE         "
    echo "             OS Auto-Detection, Environment Setup & Launcher              "
    echo "=========================================================================="
    echo -e "${CLR_RESET}"
}

log_info() {
    echo -e "${CLR_BLUE}[*]${CLR_RESET} $1"
}

log_success() {
    echo -e "${CLR_GREEN}[✓]${CLR_RESET} $1"
}

log_warning() {
    echo -e "${CLR_YELLOW}[!]${CLR_RESET} $1"
}

log_error() {
    echo -e "${CLR_RED}[✗]${CLR_RESET} $1"
}

# ------------------------------------------------------------------------------
# 1. OS & Distribution Auto-Detection
# ------------------------------------------------------------------------------
detect_os() {
    log_info "Detecting Operating System and Architecture..."
    OS_NAME="$(uname -s)"
    ARCH="$(uname -m)"
    DISTRO="unknown"
    PKG_MGR="unknown"

    if [ "$OS_NAME" != "Linux" ]; then
        log_error "This suite is exclusively built and supported on Linux (found $OS_NAME)."
        exit 1
    fi

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        DISTRO_PRETTY="$PRETTY_NAME"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
        DISTRO_PRETTY="$(cat /etc/redhat-release)"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        DISTRO_PRETTY="Debian $(cat /etc/debian_version)"
    else
        DISTRO="generic_linux"
        DISTRO_PRETTY="Generic Linux"
    fi

    # Determine package manager
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
    elif command -v zypper &>/dev/null; then
        PKG_MGR="zypper"
    elif command -v apk &>/dev/null; then
        PKG_MGR="apk"
    fi

    echo -e "    ${CLR_BOLD}Operating System:${CLR_RESET}  $DISTRO_PRETTY"
    echo -e "    ${CLR_BOLD}Kernel/Platform:${CLR_RESET}   $OS_NAME ($ARCH)"
    echo -e "    ${CLR_BOLD}Package Manager:${CLR_RESET}   $PKG_MGR"
    echo
}

# ------------------------------------------------------------------------------
# 2. Python 3 & Pip Verification
# ------------------------------------------------------------------------------
check_python() {
    log_info "Checking Python runtime environment..."

    PYTHON_BIN=""
    if command -v python3 &>/dev/null; then
        PYTHON_BIN="python3"
    elif command -v python &>/dev/null; then
        PYTHON_BIN="python"
    else
        log_error "Python 3 is not installed on this system."
        return 1
    fi

    PY_VER="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    PY_MAJOR="$($PYTHON_BIN -c 'import sys; print(sys.version_info.major)')"
    PY_MINOR="$($PYTHON_BIN -c 'import sys; print(sys.version_info.minor)')"

    if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 9 ]; }; then
        log_error "Python 3.9+ is required (found Python $PY_VER)."
        return 1
    fi

    log_success "Found Python $PY_VER ($($PYTHON_BIN --version))"
    return 0
}

# ------------------------------------------------------------------------------
# 3. System Dependencies Installer (if requested or missing)
# ------------------------------------------------------------------------------
install_system_dependencies() {
    log_info "Checking required system packages..."

    if ! check_python; then
        log_warning "Attempting to install Python 3 via package manager ($PKG_MGR)..."
        case "$PKG_MGR" in
            apt)
                sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv python3-pyqt6
                ;;
            pacman)
                sudo pacman -Sy --noconfirm python python-pip python-pyqt6
                ;;
            dnf)
                sudo dnf install -y python3 python3-pip python3-pyqt6
                ;;
            zypper)
                sudo zypper install -y python3 python3-pip python3-PyQt6
                ;;
            *)
                log_error "Automatic package installation not supported for '$PKG_MGR'. Please install Python 3 and PyQt6 manually."
                exit 1
                ;;
        esac
    fi
}

# ------------------------------------------------------------------------------
# 4. Virtual Environment Setup
# ------------------------------------------------------------------------------
setup_virtualenv() {
    VENV_DIR="$SCRIPT_DIR/.venv"

    # Check if system python already has PyQt6 working
    SYSTEM_HAS_PYQT6=false
    if python3 -c "import PyQt6" &>/dev/null; then
        SYSTEM_HAS_PYQT6=true
    fi

    if [ ! -d "$VENV_DIR" ]; then
        log_info "Creating Python virtual environment in .venv/..."
        # If system has PyQt6, enable system site packages to use system-optimized Qt libraries
        if [ "$SYSTEM_HAS_PYQT6" = true ]; then
            python3 -m venv --system-site-packages "$VENV_DIR" 2>/dev/null || python3 -m venv "$VENV_DIR"
        else
            python3 -m venv "$VENV_DIR"
        fi
        log_success "Virtual environment initialized."
    fi

    # Activate virtual environment
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"

    # Verify or install requirements
    log_info "Checking python dependencies in virtual environment..."
    if ! python -c "import PyQt6" &>/dev/null; then
        log_info "Installing PyQt6 and testing dependencies from requirements.txt..."
        pip install --upgrade pip
        pip install -r "$SCRIPT_DIR/requirements.txt"
        log_success "Dependencies installed successfully."
    else
        log_success "PyQt6 is available and ready."
    fi
}

# ------------------------------------------------------------------------------
# 5. Application Execution Commands
# ------------------------------------------------------------------------------
run_gui() {
    detect_os
    setup_virtualenv
    log_info "Launching CodeNova Password Strength Checker GUI..."
    python "$SCRIPT_DIR/main.py" "$@"
}

run_cli() {
    detect_os
    setup_virtualenv
    log_info "Launching CodeNova Password Auditor (CLI mode)..."
    python "$SCRIPT_DIR/main.py" --cli "$@"
}

run_tests() {
    detect_os
    setup_virtualenv
    log_info "Executing unit test suite..."
    python -m unittest discover -s "$SCRIPT_DIR/tests" -v
}

check_credential() {
    detect_os
    setup_virtualenv
    python "$SCRIPT_DIR/main.py" --check "$1"
}

# ------------------------------------------------------------------------------
# Main Dispatcher
# ------------------------------------------------------------------------------
print_banner

case "$1" in
    --install|-i)
        detect_os
        install_system_dependencies
        setup_virtualenv
        log_success "Installation and environment setup completed!"
        ;;
    --run|-r)
        shift
        run_gui "$@"
        ;;
    --qt)
        shift
        run_gui --qt "$@"
        ;;
    --cli|-c)
        shift
        run_cli "$@"
        ;;
    --test|-t)
        run_tests
        ;;
    --check)
        if [ -z "$2" ]; then
            log_error "Usage: ./setup.sh --check <password>"
            exit 1
        fi
        check_credential "$2"
        ;;
    --help|-h)
        echo "Usage: ./setup.sh [COMMAND]"
        echo
        echo "Commands:"
        echo "  (no args)       Auto-detect OS, configure environment, and launch clean desktop GUI"
        echo "  --run, -r       Launch the clean modern desktop application"
        echo "  --qt            Launch the native PyQt6 desktop interface"
        echo "  --install, -i   Detect OS, install required packages and configure venv"
        echo "  --cli, -c       Launch the interactive command-line interface"
        echo "  --test, -t      Run the automated unit test suite"
        echo "  --check <pwd>   Directly audit a single password string"
        echo "  --help, -h      Display this help menu"
        echo
        ;;
    *)
        # Default behavior: detect, setup, and launch GUI (or CLI fallback)
        detect_os
        setup_virtualenv
        log_info "Starting application..."
        python "$SCRIPT_DIR/main.py" "$@"
        ;;
esac
