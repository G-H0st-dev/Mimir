#!/usr/bin/env bash
#
# install.sh — checks for and installs everything MIMIR // needs.
#
# Safe to re-run: every step checks whether its target is already present
# before doing anything, so running this again after a partial install (or
# just to verify your setup) won't reinstall things or duplicate PATH/rc
# entries.
#
# Usage:
#   ./install.sh                 interactive install of everything
#   ./install.sh -y               non-interactive (assume yes)
#   ./install.sh --check-only     just report status, install nothing
#   ./install.sh --dry-run        print what would happen, change nothing
#   ./install.sh --skip-apt       skip apt-get based installs
#   ./install.sh --no-naabu-cap   skip the naabu setcap step
#   ./install.sh -h               help
#
set -uo pipefail
# Deliberately NOT using -e: one tool failing to install shouldn't abort
# the rest of the run. Each step is checked and reported individually, and
# the script exits non-zero at the end if anything required is still missing.

# ---------------------------------------------------------------------------
# Colors / logging — matches the app's own terminal palette
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_GREEN="\033[0;32m"; C_AMBER="\033[0;33m"; C_RED="\033[0;31m"
  C_CYAN="\033[0;36m"; C_DIM="\033[2m"; C_RESET="\033[0m"; C_BOLD="\033[1m"
else
  C_GREEN=""; C_AMBER=""; C_RED=""; C_CYAN=""; C_DIM=""; C_RESET=""; C_BOLD=""
fi

log()      { echo -e "${C_DIM}[*]${C_RESET} $*"; }
log_ok()   { echo -e "${C_GREEN}[+]${C_RESET} $*"; }
log_warn() { echo -e "${C_AMBER}[!]${C_RESET} $*"; }
log_err()  { echo -e "${C_RED}[x]${C_RESET} $*"; }
log_cmd()  { echo -e "${C_CYAN}\$${C_RESET} $*"; }

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
ASSUME_YES=0
CHECK_ONLY=0
DRY_RUN=0
SKIP_APT=0
NAABU_CAP=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1 ;;
    --check-only) CHECK_ONLY=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --skip-apt) SKIP_APT=1 ;;
    --no-naabu-cap) NAABU_CAP=0 ;;
    -h|--help)
      grep '^#' "$0" | sed -e '1d' -e 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      log_err "Unknown argument: $1"
      exit 1
      ;;
  esac
  shift
done

run() {
  # run <description> -- <command...>
  # Executes (or, in dry-run mode, just prints) a command.
  if [[ $DRY_RUN -eq 1 ]]; then
    log_cmd "$*"
    return 0
  fi
  "$@"
}

confirm() {
  # confirm <prompt> — returns 0 (yes) or 1 (no)
  [[ $ASSUME_YES -eq 1 ]] && return 0
  local reply
  read -r -p "$(echo -e "${C_AMBER}?${C_RESET} $1 [Y/n] ")" reply
  [[ -z "$reply" || "$reply" =~ ^[Yy] ]]
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Environment checks
# ---------------------------------------------------------------------------
echo -e "${C_BOLD}${C_GREEN}MIMIR //${C_RESET} ${C_DIM}dependency installer${C_RESET}"
echo

# ---------------------------------------------------------------------------
# Guard against running the WHOLE script as root/sudo. This script only
# needs elevated privileges for two specific things (apt package installs,
# and granting naabu's raw-socket capability) and escalates itself for
# exactly those via $SUDO further down. If the whole script is invoked as
# root instead (`sudo ./install.sh`), every Go/pip install happens under
# root's $HOME too — meaning the tools end up owned by root in /root/go/bin
# instead of your own ~/go/bin, and you'd then need sudo just to *run the
# app* afterward to reach them at all. That's a real, previously-reported
# trap, not a hypothetical.
# ---------------------------------------------------------------------------
if [[ $EUID -eq 0 ]]; then
  if [[ -n "${SUDO_USER:-}" ]]; then
    log_err "This was run with 'sudo' directly (e.g. 'sudo ./install.sh') — don't do that."
    log_err "Everything would install under root's home instead of yours ($SUDO_USER), which"
    log_err "means you'd need sudo just to run the app afterward too, to reach its own tools."
    echo
    log_err "Run it as yourself instead, without sudo:"
    log_err "    ./install.sh"
    log_err "It prompts for your sudo password automatically for the specific steps that"
    log_err "actually need it — apt package installs, and granting naabu raw-socket"
    log_err "capability. Nothing else here requires elevated privileges."
    echo
    log_warn "If you've already run this with sudo before, your tools may currently be under"
    log_warn "/root/go/bin owned by root. Check: ls -la ~/go/bin  (should show YOUR username,"
    log_warn "not root). If it shows root, or that directory doesn't exist under your own home"
    log_warn "at all, re-run this script as yourself to install everything in the right place."
    exit 1
  else
    log_warn "Running as root (not via sudo — e.g. you're already logged in as root, or this"
    log_warn "is a root shell/container). Tools will install under /root, and you'll need to"
    log_warn "run the app as root too to reach them. That's fine if this whole machine is"
    log_warn "root-only (a throwaway VM, some containers), but if you have a regular user"
    log_warn "account, running this as that user instead is usually what you want."
    if ! confirm "Continue as root anyway?"; then
      exit 1
    fi
  fi
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  log_warn "This doesn't look like Linux ($(uname -s)). This script targets Kali/Debian — proceed at your own risk."
fi

if command -v apt-get >/dev/null 2>&1; then
  HAVE_APT=1
else
  HAVE_APT=0
  log_warn "apt-get not found — this doesn't look like Kali/Debian. apt-based steps will be skipped."
  SKIP_APT=1
fi

if [[ $EUID -eq 0 ]]; then
  SUDO=""
  log "Running as root — no sudo needed for apt/setcap steps."
else
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    SUDO=""
    log_warn "Not root and no sudo found — apt/setcap steps that need elevation may fail."
  fi
fi

# ---------------------------------------------------------------------------
# Preflight network check — `go install` and `git clone` both need
# outbound HTTPS to proxy.golang.org/github.com specifically, and
# "Network is unreachable" (not a timeout, not a DNS failure) on a VM is
# one of the most common, well-known causes: an IPv6 route is configured
# but nothing upstream actually routes it, so any destination that
# resolves to an IPv6 address first fails outright while others succeed
# — confirmed directly as the cause of katana/gau specifically failing
# to install while other tools were fine. Catching this up front means a
# clear, actionable message here instead of a cryptic failure buried
# deep inside a `go install` later.
# ---------------------------------------------------------------------------
check_https_reachable() {
  # check_https_reachable <host> — returns 0 if a TCP connection to
  # <host>:443 succeeds, 1 otherwise. Uses bash's own /dev/tcp rather
  # than curl/nc, so this works even before anything else is installed.
  timeout 5 bash -c "exec 3<>/dev/tcp/$1/443" 2>/dev/null
}

NETWORK_PREFLIGHT_FAILED=0
for preflight_host in proxy.golang.org github.com; do
  if ! check_https_reachable "$preflight_host"; then
    NETWORK_PREFLIGHT_FAILED=1
  fi
done

if [[ $NETWORK_PREFLIGHT_FAILED -eq 1 ]]; then
  log_warn "Couldn't reach one or more of proxy.golang.org / github.com over HTTPS (443) just now."
  log_warn "This affects 'go install' (katana, httpx, gau, shuffledns, and others) and 'git"
  log_warn "clone' (the n0kovo wordlist repo) specifically — apt-based installs may still work fine."
  echo
  log_warn "The single most common cause of this exact symptom on a VM: an IPv6 route is"
  log_warn "configured but nothing upstream actually routes it, so any destination that"
  log_warn "resolves to an IPv6 address first fails with 'Network is unreachable' while"
  log_warn "others succeed. Quick check — if this works but a plain 'curl https://github.com'"
  log_warn "doesn't, that confirms it:"
  log_warn "    curl -4 -v https://github.com"
  echo
  log_warn "If that's the cause, the fix (needs sudo):"
  log_warn "    sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1"
  log_warn "    sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1"
  log_warn "Make it permanent by adding both as 'net.ipv6.conf.all.disable_ipv6 = 1' (and the"
  log_warn "'default' line) to /etc/sysctl.conf, then 'sudo sysctl -p'."
  echo
  if ! confirm "Continue anyway? (apt-based tools should still install fine either way)"; then
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# apt packages: go toolchain, amass, whois, theHarvester
# ---------------------------------------------------------------------------
APT_DID_UPDATE=0
apt_ensure_updated() {
  if [[ $APT_DID_UPDATE -eq 1 || $SKIP_APT -eq 1 ]]; then return; fi
  if [[ $CHECK_ONLY -eq 1 ]]; then return; fi
  if confirm "Run 'apt-get update' first?"; then
    run $SUDO apt-get update -qq
  fi
  APT_DID_UPDATE=1
}

apt_install_if_missing() {
  # apt_install_if_missing <check_cmd> <apt_package> [apt_package2 ...]
  local check_cmd="$1"; shift
  local packages=("$@")
  if command -v "$check_cmd" >/dev/null 2>&1; then
    log_ok "$check_cmd already installed"
    return 0
  fi
  if [[ $CHECK_ONLY -eq 1 ]]; then
    log_warn "$check_cmd missing (would install: ${packages[*]})"
    return 1
  fi
  if [[ $SKIP_APT -eq 1 ]]; then
    log_warn "$check_cmd missing — skipping apt install (--skip-apt set)"
    return 1
  fi
  log "$check_cmd missing — installing ${packages[*]} via apt"
  apt_ensure_updated
  if run $SUDO apt-get install -y "${packages[@]}"; then
    log_ok "installed ${packages[*]}"
  else
    log_err "failed to install ${packages[*]} — you may need to install it manually"
    return 1
  fi
}

log "${C_BOLD}Go toolchain${C_RESET}"
apt_install_if_missing go golang-go

log
log "${C_BOLD}apt-packaged recon tools${C_RESET}"
apt_install_if_missing amass amass
apt_install_if_missing whois whois
apt_install_if_missing dig dnsutils
apt_install_if_missing nmap nmap
apt_install_if_missing whatweb whatweb
apt_install_if_missing ffuf ffuf
apt_install_if_missing wpscan wpscan
# massdns is a dependency of shuffledns (installed further below), not a
# standalone recon tool — installed here so it's in place before that.
apt_install_if_missing massdns massdns
apt_install_if_missing spiderfoot spiderfoot

# ---------------------------------------------------------------------------
# SecLists — not a program, a directory of wordlist files apt drops at
# /usr/share/seclists/. Checked by directory presence rather than a
# binary, since there's nothing to run `command -v` against. This is
# specifically what makes the ffuf/directory-discovery wordlist
# recommendations usable out of the box, rather than requiring a manual
# download before ffuf's wordlist picker has anything real to offer.
# ---------------------------------------------------------------------------
install_seclists() {
  if [[ -d /usr/share/seclists/Discovery/Web-Content ]]; then
    log_ok "SecLists already installed"
    return 0
  fi
  if [[ $CHECK_ONLY -eq 1 ]]; then
    log_warn "SecLists missing (would install: apt install seclists)"
    return 1
  fi
  if [[ $SKIP_APT -eq 1 ]]; then
    log_warn "SecLists missing — skipping apt install (--skip-apt set)"
    return 1
  fi
  log "SecLists missing — installing seclists via apt"
  apt_ensure_updated
  if run $SUDO apt-get install -y seclists; then
    log_ok "installed SecLists"
  else
    log_err "failed to install SecLists — the ffuf/directory-discovery wordlist recommendations won't be available"
    return 1
  fi
}
install_seclists

# ---------------------------------------------------------------------------
# n0kovo_subdomains — the current go-to subdomain-bruteforce wordlist
# (confirmed against several current pentest wordlist guides, not just
# assumed), used for amass/dnsx/shuffledns. Not an apt package — cloned
# directly from its GitHub repo into this app's own directory.
# ---------------------------------------------------------------------------
N0KOVO_DIR="$SCRIPT_DIR/wordlists-src/n0kovo_subdomains"
install_n0kovo_subdomains() {
  if [[ -f "$N0KOVO_DIR/n0kovo_subdomains_large.txt" ]]; then
    log_ok "n0kovo_subdomains already present"
    return 0
  fi
  if ! command -v git >/dev/null 2>&1; then
    log_warn "git not found — skipping n0kovo_subdomains (needed to clone it)"
    return 1
  fi
  if [[ $CHECK_ONLY -eq 1 ]]; then
    log_warn "n0kovo_subdomains missing (would clone github.com/n0kovo/n0kovo_subdomains)"
    return 1
  fi
  log "n0kovo_subdomains missing — cloning github.com/n0kovo/n0kovo_subdomains"
  mkdir -p "$SCRIPT_DIR/wordlists-src"
  if run git clone --depth 1 https://github.com/n0kovo/n0kovo_subdomains.git "$N0KOVO_DIR"; then
    log_ok "cloned n0kovo_subdomains"
  else
    log_err "failed to clone n0kovo_subdomains — subdomain-bruteforce wordlist recommendations won't be available"
    return 1
  fi
}
install_n0kovo_subdomains

# Checks for recon-cli specifically (not recon-ng) since that's the
# non-interactive binary this app actually invokes for automation — both
# come from the same apt package, this just makes sure the RIGHT one is
# what gets detected as present.
apt_install_if_missing recon-cli recon-ng

# Kali's theHarvester package installs the binary as `theHarvester`
# (capital H); some distros alias a lowercase `theharvester` too. Check both.
if command -v theHarvester >/dev/null 2>&1 || command -v theharvester >/dev/null 2>&1; then
  log_ok "theHarvester already installed"
else
  if [[ $CHECK_ONLY -eq 1 ]]; then
    log_warn "theHarvester missing (would install: theharvester)"
  elif [[ $SKIP_APT -eq 1 ]]; then
    log_warn "theHarvester missing — skipping apt install (--skip-apt set)"
  else
    log "theHarvester missing — installing via apt"
    apt_ensure_updated
    if run $SUDO apt-get install -y theharvester; then
      log_ok "installed theharvester"
    else
      log_err "failed to install theharvester — you may need to install it manually"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Go-based recon tools: subfinder, dnsx, httpx, naabu, assetfinder
# ---------------------------------------------------------------------------
echo
log "${C_BOLD}Go-based recon tools${C_RESET}"

if ! command -v go >/dev/null 2>&1; then
  log_err "go still isn't on PATH — can't install Go-based tools (subfinder, dnsx, httpx, naabu, assetfinder)."
  log_err "Install the Go toolchain first, then re-run this script."
  GO_OK=0
else
  GO_OK=1
  GOBIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
  export PATH="$PATH:$GOBIN"
fi

# ---------------------------------------------------------------------------
# Some networks route to proxy.golang.org's IPv6 address in a way that's
# broken (the "dial tcp [2c0f:...]:443: connect: network is unreachable"
# error) even when IPv4 to that exact host works fine and other IPv6
# destinations are unaffected — confirmed directly as a real, reproducible
# failure mode on an actual VM, not a hypothetical. Disabling IPv6
# system-wide did NOT fix it (Go's own networking doesn't consistently
# respect that setting the way curl/ping do). The fix that DID work:
# routing `go install` around proxy.golang.org entirely, straight to each
# module's own source repo (GitHub, for every tool here) — confirmed
# IPv4-only in the same diagnosis that found this.
# ---------------------------------------------------------------------------
GOPROXY_DIRECT_APPLIED=0
DNS_FALLBACK_APPLIED=0

# ---------------------------------------------------------------------------
# A deeper-layer fallback than the GOPROXY switch below: switching GOPROXY
# to a different domain doesn't help if the configured DNS resolver can't
# resolve *that* domain either — confirmed directly, switching to
# goproxy.cn still failed with "no such host" on a network whose router
# resolved github.com/google.com fine but failed specifically on gopkg.in
# and goproxy.cn. That pattern (some domains resolve, others via the same
# resolver don't) points at the resolver itself being selectively
# unreliable, not at which domain was picked. Offered interactively
# (respects -y) since rewriting DNS config is a real system change, not
# a Go-specific one, and detects which of resolvectl/NetworkManager/plain
# resolv.conf is actually in play rather than guessing.
# ---------------------------------------------------------------------------
apply_dns_fallback() {
  if [[ $DNS_FALLBACK_APPLIED -eq 1 ]]; then return 1; fi
  DNS_FALLBACK_APPLIED=1
  log_warn "That's a DNS resolution failure, not a connectivity one — the configured resolver"
  log_warn "isn't answering for this domain specifically (a router/ISP resolver being"
  log_warn "selectively unreliable for certain domains is a common, confirmed cause of exactly"
  log_warn "this). Switching GOPROXY doesn't help if DNS itself can't resolve the new target."
  if [[ $CHECK_ONLY -eq 1 || $DRY_RUN -eq 1 ]]; then
    log_warn "(would offer to temporarily point DNS at 1.1.1.1/1.0.0.1 here — skipped in this mode)"
    return 1
  fi
  if ! confirm "Temporarily point this machine's DNS at 1.1.1.1/1.0.0.1 for the rest of this session?"; then
    log_warn "skipped — re-run once DNS resolves for the affected domain(s), or fix it manually"
    return 1
  fi
  if command -v resolvectl >/dev/null 2>&1; then
    local iface
    iface="$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')"
    if [[ -z "$iface" ]]; then
      log_warn "couldn't determine the active network interface for resolvectl — skipping"
      return 1
    fi
    log_cmd "sudo resolvectl dns $iface 1.1.1.1 1.0.0.1"
    $SUDO resolvectl dns "$iface" 1.1.1.1 1.0.0.1
  elif command -v nmcli >/dev/null 2>&1 && nmcli -t -f DEVICE,STATE device 2>/dev/null | grep -q ":connected"; then
    local conn
    conn="$(nmcli -t -f NAME connection show --active 2>/dev/null | head -1)"
    if [[ -z "$conn" ]]; then
      log_warn "couldn't determine the active NetworkManager connection — skipping"
      return 1
    fi
    log_cmd "sudo nmcli connection modify \"$conn\" ipv4.dns \"1.1.1.1 1.0.0.1\" ipv4.ignore-auto-dns yes"
    $SUDO nmcli connection modify "$conn" ipv4.dns "1.1.1.1 1.0.0.1" ipv4.ignore-auto-dns yes
    log_cmd "sudo nmcli connection up \"$conn\""
    $SUDO nmcli connection up "$conn" >/dev/null 2>&1
  else
    log_cmd "echo 'nameserver 1.1.1.1' | sudo tee /etc/resolv.conf"
    echo "nameserver 1.1.1.1" | $SUDO tee /etc/resolv.conf >/dev/null
    log_warn "wrote directly to /etc/resolv.conf — this may get overwritten by DHCP/NetworkManager"
    log_warn "on reconnect; if this fixes things, make it permanent via your distro's normal DNS"
    log_warn "settings rather than relying on this each time."
  fi
  return 0
}

go_install_with_ipv6_fallback() {
  # go_install_with_ipv6_fallback <go-install-path> — same contract as
  # `run go install <pkg>`: streams output as it happens, returns go
  # install's own exit status. Transparently retries once, switching
  # GOPROXY, if the failure output matches the known broken-IPv6-route
  # signature — any other failure is reported exactly as before, with
  # no retry.
  #
  # This signature isn't just "network is unreachable" against
  # proxy.golang.org — confirmed directly on a real VM, the same
  # underlying broken IPv6 route also surfaces as "cannot assign
  # requested address" against golang.org (hit when resolving vanity
  # import paths like golang.org/x/net or golang.org/x/sys, which
  # go install needs to contact directly for) and as a bare DNS lookup
  # failure for gopkg.in (another vanity-import domain, hit the same
  # way). GOPROXY=direct alone doesn't fix this: it stops go from
  # talking to proxy.golang.org, but vanity imports still require
  # contacting golang.org/gopkg.in directly regardless — confirmed
  # directly too, GOPROXY=direct got several tools installed but then
  # failed on dalfox specifically once it needed golang.org/x/sys and
  # gopkg.in/yaml.v2. Routing through a third-party proxy instead
  # (goproxy.cn — a long-established, full-featured, rate-limit-free
  # public Go proxy that also proxies sum.golang.org, so checksum
  # verification stays on) avoids the client ever needing to contact
  # any of these domains directly, whichever one would have failed.
  local pkg="$1"
  if [[ $DRY_RUN -eq 1 ]]; then
    log_cmd "go install $pkg"
    return 0
  fi
  local output status
  output="$(go install "$pkg" 2>&1)"
  status=$?
  echo "$output"
  if [[ $status -ne 0 && $GOPROXY_DIRECT_APPLIED -eq 0 ]] \
     && echo "$output" | grep -qiE "network is unreachable|cannot assign requested address|no such host" \
     && echo "$output" | grep -qiE "proxy\.golang\.org|golang\.org|gopkg\.in|\[[0-9a-f:]+\]:443"; then
    log_warn "That's the known broken-IPv6-route failure — a real, confirmed issue on some"
    log_warn "networks that shows up in more than one form (proxy.golang.org unreachable,"
    log_warn "golang.org unreachable while resolving a vanity import path, gopkg.in failing DNS"
    log_warn "lookup — all the same underlying cause). Disabling IPv6 system-wide does not fix"
    log_warn "it, and switching to GOPROXY=direct alone isn't enough either, since vanity import"
    log_warn "paths still need to contact golang.org/gopkg.in directly regardless. Routing"
    log_warn "through a third-party Go proxy instead avoids contacting any of them directly —"
    log_warn "this is permanent (via 'go env -w'), so it only needs to happen once for the rest"
    log_warn "of this run:"
    log_cmd "go env -w GOPROXY=https://goproxy.cn,direct"
    go env -w GOPROXY=https://goproxy.cn,direct
    GOPROXY_DIRECT_APPLIED=1
    log "retrying: go install $pkg"
    output="$(go install "$pkg" 2>&1)"
    status=$?
    echo "$output"
  fi
  # Second tier: the GOPROXY switch above doesn't help if DNS itself
  # can't resolve the new target either — see apply_dns_fallback above.
  if [[ $status -ne 0 && $DNS_FALLBACK_APPLIED -eq 0 ]] \
     && echo "$output" | grep -qiE "no such host"; then
    if apply_dns_fallback; then
      log "retrying: go install $pkg"
      output="$(go install "$pkg" 2>&1)"
      status=$?
      echo "$output"
    fi
  fi
  return $status
}

go_install_if_missing() {
  # go_install_if_missing <binary_name> <go_install_path>
  local bin="$1"; local pkg="$2"
  if command -v "$bin" >/dev/null 2>&1; then
    log_ok "$bin already installed"
    return 0
  fi
  if [[ $GO_OK -eq 0 ]]; then
    log_warn "$bin missing (needs Go toolchain, see above)"
    return 1
  fi
  if [[ $CHECK_ONLY -eq 1 ]]; then
    log_warn "$bin missing (would run: go install $pkg)"
    return 1
  fi
  log "$bin missing — running: go install $pkg"
  if go_install_with_ipv6_fallback "$pkg"; then
    log_ok "installed $bin"
  else
    log_err "failed to install $bin"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# httpx needs its own check, not the generic one above: Python's
# `httpx[cli]` HTTP client package installs a console script with the
# *exact same binary name* as ProjectDiscovery's recon tool. A plain
# `command -v httpx` only proves *something* called httpx exists — it
# can't tell which one, so a system with only the Python one installed
# would wrongly report "already installed" and skip installing the real
# tool, which is exactly the bug this replaces.
# ---------------------------------------------------------------------------
httpx_binary_is_correct() {
  # httpx_binary_is_correct <path-to-binary> — 0 if it behaves like
  # ProjectDiscovery's httpx, 1 if it looks like the wrong program.
  local bin="$1"
  local out
  out="$("$bin" -version 2>&1 || true)"
  if echo "$out" | grep -qE "No such option|Usage: httpx \[OPTIONS\] URL"; then
    return 1
  fi
  return 0
}

find_working_httpx() {
  # Prints the path to a working ProjectDiscovery httpx if one exists
  # anywhere on PATH (checking every directory, not just the first
  # match — same idea as `which -a`), else prints nothing and fails.
  local dir
  local IFS=':'
  for dir in $PATH; do
    [[ -x "$dir/httpx" ]] || continue
    if httpx_binary_is_correct "$dir/httpx"; then
      echo "$dir/httpx"
      return 0
    fi
  done
  return 1
}

check_httpx() {
  local working
  working="$(find_working_httpx || true)"
  if [[ -n "$working" ]]; then
    log_ok "httpx already installed (verified working: $working)"
    return 0
  fi

  # Nothing that behaves correctly was found. Explain *why* if there's a
  # decoy sitting there, so this doesn't look like a mystery.
  if command -v httpx >/dev/null 2>&1; then
    log_warn "found a program called 'httpx' at $(command -v httpx), but it doesn't behave like ProjectDiscovery's recon tool"
    log_warn "(this is almost always Python's httpx[cli] HTTP client — same binary name, unrelated tool)"
  else
    log_warn "httpx not found on PATH"
  fi

  if [[ $GO_OK -eq 0 ]]; then
    log_warn "can't install the real httpx (needs Go toolchain, see above)"
    return 1
  fi
  if [[ $CHECK_ONLY -eq 1 ]]; then
    log_warn "would install ProjectDiscovery's httpx (would run: go install github.com/projectdiscovery/httpx/cmd/httpx@latest)"
    return 1
  fi

  if confirm "Install ProjectDiscovery's httpx now?"; then
    log "installing httpx — running: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    if go_install_with_ipv6_fallback github.com/projectdiscovery/httpx/cmd/httpx@latest; then
      log_ok "installed httpx to $GOBIN"
      working="$(find_working_httpx || true)"
      if [[ -n "$working" ]]; then
        log_ok "verified working httpx: $working"
      else
        log_warn "installed, but couldn't verify it responds correctly — check manually: $GOBIN/httpx -version"
      fi
    else
      log_err "failed to install httpx"
      return 1
    fi
  else
    log_warn "skipped — httpx-dependent scan steps won't work until this is resolved"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Go version preflight — katana specifically needs Go 1.26+ (the highest
# bar among the newly-added tools), nuclei needs 1.24.2+, shuffledns needs
# 1.24+. Debian/Kali's apt-packaged Go tends to lag behind upstream
# releases, so this checks the actual installed version up front and
# explains what's going on, rather than letting two or three different
# `go install` commands fail later with build errors that don't obviously
# point back to "the Go version is too old."
# ---------------------------------------------------------------------------
check_go_version_for_new_tools() {
  if [[ $GO_OK -eq 0 ]]; then
    return 0
  fi
  local ver_str major minor
  ver_str="$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | sed 's/^go//')"
  if [[ -z "$ver_str" ]]; then
    log_warn "couldn't determine the installed Go version — skipping this preflight check"
    return 0
  fi
  major="$(echo "$ver_str" | cut -d. -f1)"
  minor="$(echo "$ver_str" | cut -d. -f2)"
  if (( major > 1 || (major == 1 && minor >= 26) )); then
    log_ok "Go $ver_str — new enough for katana, nuclei, and shuffledns"
    GO_NEW_ENOUGH_FOR_KATANA=1
    return 0
  fi
  GO_NEW_ENOUGH_FOR_KATANA=0
  log_warn "Go $ver_str is installed. katana needs Go 1.26+ and will likely fail to install below"
  log_warn "(nuclei needs 1.24.2+, shuffledns needs 1.24+ — those two may still be fine at this version)."
  log_warn "Debian/Kali's apt-packaged Go often lags behind upstream releases. If katana's install"
  log_warn "fails, install a current Go directly from https://go.dev/dl/ and re-run this script —"
  log_warn "apt's golang-go isn't required, it's just this script's default source for it."
}
# Unknown by default — if the check above never ran (GO_OK=0) or never
# resolved a version string, install_katana's own failure path below
# falls back to treating the Go version as a real, unruled-out
# possibility, same as before this was added.
GO_NEW_ENOUGH_FOR_KATANA=-1
check_go_version_for_new_tools

# ---------------------------------------------------------------------------
# katana needs CGO_ENABLED=1 at build time specifically — not a typo, and
# not something the generic go_install_if_missing helper below handles,
# so this gets its own install function that sets it explicitly (rather
# than relying on bash's `VAR=val command` prefix syntax working through
# the run() wrapper, which is avoidable ambiguity worth just not having).
# ---------------------------------------------------------------------------
install_katana() {
  if command -v katana >/dev/null 2>&1; then
    log_ok "katana already installed"
    return 0
  fi
  if [[ $GO_OK -eq 0 ]]; then
    log_warn "katana missing (needs Go toolchain, see above)"
    return 1
  fi
  if [[ $CHECK_ONLY -eq 1 ]]; then
    log_warn "katana missing (would run: CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest)"
    return 1
  fi
  log "katana missing — running: CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest"
  log "${C_DIM}(katana specifically needs CGO_ENABLED=1 — a plain 'go install' can fail or silently${C_RESET}"
  log "${C_DIM} build without some functionality; this is intentional, not a mistake)${C_RESET}"
  export CGO_ENABLED=1
  local result=0
  go_install_with_ipv6_fallback github.com/projectdiscovery/katana/cmd/katana@latest || result=1
  unset CGO_ENABLED
  if [[ $result -eq 0 ]]; then
    log_ok "installed katana"
  else
    if [[ $GO_NEW_ENOUGH_FOR_KATANA -eq 1 ]]; then
      # The preflight check above already confirmed the installed Go
      # version is new enough — repeating "this usually means Go is too
      # old" here anyway would be actively misleading in that case, not
      # just unhelpful. Point at the real cause instead: the actual
      # error from `go install` is already printed just above this,
      # from inside go_install_with_ipv6_fallback.
      log_err "failed to install katana — Go's version was already confirmed new enough above,"
      log_err "so that's not the cause here. See the actual error output just above this line —"
      log_err "common causes at this point: gcc/build-essential missing (katana needs CGO, see"
      log_err "below), a network issue distinct from the proxy.golang.org one already handled,"
      log_err "or disk space."
      if ! command -v gcc >/dev/null 2>&1 && ! command -v cc >/dev/null 2>&1; then
        log_err "confirmed: no C compiler found on PATH (gcc/cc) — katana needs one, since it"
        log_err "builds with CGO_ENABLED=1. Install it: sudo apt-get install -y build-essential"
      fi
    else
      log_err "failed to install katana — this usually means Go is older than the 1.26+ katana requires;"
      log_err "check 'go version' and consider installing a newer Go from https://go.dev/dl/"
    fi
    return 1
  fi
}

# ---------------------------------------------------------------------------
# shuffledns has a documented history of `go install` failing outright on
# Kali specifically (a longstanding upstream/environment issue, unrelated
# to this app) — still attempted here as the current official method, but
# with an explicit compile-from-source fallback on failure rather than
# just reporting "failed" and leaving the person to go find that out.
# ---------------------------------------------------------------------------
install_shuffledns() {
  if command -v shuffledns >/dev/null 2>&1; then
    log_ok "shuffledns already installed"
    return 0
  fi
  if [[ $GO_OK -eq 0 ]]; then
    log_warn "shuffledns missing (needs Go toolchain, see above)"
    return 1
  fi
  if [[ $CHECK_ONLY -eq 1 ]]; then
    log_warn "shuffledns missing (would run: go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest)"
    return 1
  fi
  log "shuffledns missing — running: go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  if go_install_with_ipv6_fallback github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest; then
    log_ok "installed shuffledns"
  else
    log_err "failed to install shuffledns via 'go install' — there's a documented history of this"
    log_err "specific failure on Kali (an upstream/environment issue, not something this app can fix)."
    log_err "If that's what just happened, compile from source instead:"
    log_err "  git clone https://github.com/projectdiscovery/shuffledns.git"
    log_err "  cd shuffledns/cmd/shuffledns && go build . && sudo mv shuffledns /usr/local/bin/"
    return 1
  fi
}

go_install_if_missing subfinder    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go_install_if_missing dnsx         github.com/projectdiscovery/dnsx/cmd/dnsx@latest
check_httpx
go_install_if_missing naabu        github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go_install_if_missing assetfinder  github.com/tomnomnom/assetfinder@latest
go_install_if_missing gowitness    github.com/sensepost/gowitness@latest
go_install_if_missing gau           github.com/lc/gau/v2/cmd/gau@latest
go_install_if_missing nuclei        github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go_install_if_missing dalfox        github.com/hahwul/dalfox/v2@latest
install_katana
install_shuffledns

# ---------------------------------------------------------------------------
# recon-ng modules aren't available just from installing the base package
# — each one needs a one-time `marketplace install` before recon-cli can
# load it, the same kind of one-time setup step nuclei's template
# download and webanalyze's old database step were. Only the three
# keyless modules this app actually runs by default get installed here;
# see README for how to add more once you've configured their API keys
# inside recon-ng itself.
# ---------------------------------------------------------------------------
RECON_NG_MODULES=(
  "recon/domains-hosts/hackertarget"
  "recon/domains-hosts/bing_domain_web"
  "recon/domains-contacts/whois_pocs"
)
if command -v recon-cli >/dev/null 2>&1; then
  echo
  log "${C_BOLD}recon-ng modules${C_RESET}"
  if [[ $CHECK_ONLY -eq 1 ]]; then
    log_warn "would install recon-ng modules: ${RECON_NG_MODULES[*]}"
  else
    for mod in "${RECON_NG_MODULES[@]}"; do
      if run recon-cli -C "marketplace install $mod"; then
        log_ok "recon-ng module ready: $mod"
      else
        log_warn "couldn't install recon-ng module '$mod' — this app will just skip it at scan time; try"
        log_warn "  'marketplace install $mod' yourself inside recon-ng to see the actual error"
      fi
    done
  fi
fi

# ---------------------------------------------------------------------------
# Make sure $GOBIN is actually on PATH for future shells, not just this run
# ---------------------------------------------------------------------------
if [[ $GO_OK -eq 1 && $CHECK_ONLY -eq 0 ]]; then
  echo
  log "${C_BOLD}PATH setup${C_RESET}"
  PATH_LINE="export PATH=\$PATH:$GOBIN"
  FISH_CONFIG="$HOME/.config/fish/config.fish"

  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [[ -f "$rc" ]] || continue
    if grep -qF "$GOBIN" "$rc" 2>/dev/null; then
      log_ok "$GOBIN already referenced in $rc"
    else
      if [[ $DRY_RUN -eq 1 ]]; then
        log_cmd "echo '$PATH_LINE' >> $rc"
      else
        echo "$PATH_LINE" >> "$rc"
        log_ok "added $GOBIN to PATH in $rc"
      fi
    fi
  done

  # fish uses a different config file *and* different syntax — "export
  # PATH=..." isn't valid fish, so appending it to .bashrc/.zshrc alone
  # silently does nothing for a fish user, which is a real reason
  # "source ~/.bashrc" wouldn't fix anything for them.
  if [[ -f "$FISH_CONFIG" ]]; then
    if grep -qF "$GOBIN" "$FISH_CONFIG" 2>/dev/null; then
      log_ok "$GOBIN already referenced in $FISH_CONFIG"
    else
      FISH_LINE="fish_add_path $GOBIN"
      if [[ $DRY_RUN -eq 1 ]]; then
        log_cmd "echo '$FISH_LINE' >> $FISH_CONFIG"
      else
        echo "$FISH_LINE" >> "$FISH_CONFIG"
        log_ok "added $GOBIN to PATH in $FISH_CONFIG (fish)"
      fi
    fi
  fi

  echo
  log_warn "This only affects NEW shells — your current terminal won't see it until one of:"
  case "$(basename "${SHELL:-bash}")" in
    zsh)  echo -e "    ${C_CYAN}source ~/.zshrc${C_RESET}" ;;
    fish) echo -e "    ${C_CYAN}source ~/.config/fish/config.fish${C_RESET}" ;;
    *)    echo -e "    ${C_CYAN}source ~/.bashrc${C_RESET}" ;;
  esac
  echo -e "    — or open a new terminal —"
  echo -e "    — or, works immediately in THIS terminal, no sourcing needed: —"
  echo -e "    ${C_CYAN}export PATH=\"\$PATH:$GOBIN\"${C_RESET}"
  echo
  echo -e "  ${C_DIM}None of the above is actually required to *run the app* — MIMIR //${C_RESET}"
  echo -e "  ${C_DIM}checks $GOBIN directly at its own startup, independent of your shell's${C_RESET}"
  echo -e "  ${C_DIM}PATH, so it finds these tools either way. This only matters if you want${C_RESET}"
  echo -e "  ${C_DIM}to run subfinder/httpx/etc. yourself, directly from the command line.${C_RESET}"
  echo -e "  ${C_DIM}If you're just trying to get the app working: python3 app.py${C_RESET}"
fi

# ---------------------------------------------------------------------------
# Python-installed recon tools (pip) — crosslinked, user-scanner
# ---------------------------------------------------------------------------
echo
log "${C_BOLD}Python-installed recon tools${C_RESET}"

pip_install_if_missing() {
  # pip_install_if_missing <binary_name> <pip_package>
  local bin="$1"; local pkg="$2"
  if command -v "$bin" >/dev/null 2>&1; then
    log_ok "$bin already installed"
    return 0
  fi
  if [[ -z "$PYTHON_BIN" ]]; then
    log_warn "$bin missing (needs python3, see below)"
    return 1
  fi
  if [[ $CHECK_ONLY -eq 1 ]]; then
    log_warn "$bin missing (would run: pip install $pkg --break-system-packages)"
    return 1
  fi
  log "$bin missing — running: pip install $pkg --break-system-packages"
  if run "$PYTHON_BIN" -m pip install "$pkg" --break-system-packages -q; then
    log_ok "installed $bin"
  else
    log_err "failed to install $bin — try running manually: $PYTHON_BIN -m pip install $pkg --break-system-packages"
    return 1
  fi
}

# PYTHON_BIN is set further down in the "Python dependencies" section below,
# but crosslinked needs python3 too, so resolve it here as well (harmless
# to compute twice — it's just `command -v`).
PYTHON_BIN="$(command -v python3 || true)"
pip_install_if_missing crosslinked crosslinked
pip_install_if_missing user-scanner user-scanner

# ---------------------------------------------------------------------------
# naabu capabilities — lets it do raw SYN scans without running as root
# ---------------------------------------------------------------------------
if [[ $NAABU_CAP -eq 1 && $CHECK_ONLY -eq 0 ]]; then
  echo
  log "${C_BOLD}naabu capabilities${C_RESET}"
  NAABU_PATH="$(command -v naabu || true)"
  if [[ -z "$NAABU_PATH" ]]; then
    log_warn "naabu not found — skipping setcap"
  elif command -v setcap >/dev/null 2>&1; then
    if command -v getcap >/dev/null 2>&1 && getcap "$NAABU_PATH" 2>/dev/null | grep -q cap_net_raw; then
      log_ok "naabu already has cap_net_raw/cap_net_admin — no sudo needed to run it"
    else
      if confirm "Grant naabu raw-socket capability so it doesn't need sudo? ($NAABU_PATH)"; then
        if run $SUDO setcap cap_net_raw,cap_net_admin=eip "$NAABU_PATH"; then
          log_ok "capability set — naabu can now run without sudo"
        else
          log_warn "setcap failed — you'll need to run the app with sudo for naabu's SYN scans, or setcap manually"
        fi
      fi
    fi
  else
    log_warn "setcap not found (package: libcap2-bin) — skipping. Run naabu steps with sudo instead."
  fi
fi

# ---------------------------------------------------------------------------
# Python dependencies for the app itself
# ---------------------------------------------------------------------------
echo
log "${C_BOLD}Python dependencies${C_RESET}"

PYTHON_BIN="$(command -v python3 || true)"
if [[ -z "$PYTHON_BIN" ]]; then
  log_err "python3 not found — install it before running MIMIR //"
else
  log_ok "python3 found ($($PYTHON_BIN --version 2>&1))"
  REQ_FILE="$SCRIPT_DIR/requirements.txt"
  if [[ ! -f "$REQ_FILE" ]]; then
    log_warn "requirements.txt not found next to this script — skipping pip install"
  elif [[ $CHECK_ONLY -eq 1 ]]; then
    if "$PYTHON_BIN" -c "import fastapi, uvicorn, pydantic, multipart, textual" >/dev/null 2>&1; then
      log_ok "fastapi/uvicorn/pydantic/multipart/textual already importable"
    else
      log_warn "fastapi/uvicorn/pydantic/multipart/textual not all importable (would run: pip install -r requirements.txt --break-system-packages)"
    fi
  else
    if "$PYTHON_BIN" -c "import fastapi, uvicorn, pydantic, multipart, textual" >/dev/null 2>&1; then
      log_ok "fastapi/uvicorn/pydantic/multipart/textual already importable"
    else
      log "installing Python dependencies from requirements.txt"
      if run "$PYTHON_BIN" -m pip install -r "$REQ_FILE" --break-system-packages -q; then
        log_ok "Python dependencies installed"
      else
        log_err "pip install failed — try running manually: $PYTHON_BIN -m pip install -r requirements.txt --break-system-packages"
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Final status summary
# ---------------------------------------------------------------------------
echo
echo -e "${C_BOLD}${C_GREEN}Status summary${C_RESET}"
echo

REQUIRED_MISSING=0
OPTIONAL_MISSING=0

print_status() {
  # print_status <label> <cmd1> [cmd2 ...]   — ok if ANY of cmd1/cmd2/... exists
  local label="$1"; shift
  local found=""
  for c in "$@"; do
    if command -v "$c" >/dev/null 2>&1; then found="$c"; break; fi
  done
  if [[ -n "$found" ]]; then
    printf "  ${C_GREEN}%-14s${C_RESET} %s\n" "available" "$label"
  else
    printf "  ${C_RED}%-14s${C_RESET} %s\n" "missing" "$label"
    return 1
  fi
}

print_status "subfinder"    subfinder    || REQUIRED_MISSING=$((REQUIRED_MISSING+1))
print_status "dnsx"         dnsx         || REQUIRED_MISSING=$((REQUIRED_MISSING+1))
if find_working_httpx >/dev/null 2>&1; then
  printf "  ${C_GREEN}%-14s${C_RESET} %s\n" "available" "httpx"
else
  if command -v httpx >/dev/null 2>&1; then
    printf "  ${C_RED}%-14s${C_RESET} %s\n" "missing" "httpx (wrong-tool collision — see above)"
  else
    printf "  ${C_RED}%-14s${C_RESET} %s\n" "missing" "httpx"
  fi
  REQUIRED_MISSING=$((REQUIRED_MISSING+1))
fi
print_status "amass"        amass        || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "assetfinder"  assetfinder  || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "naabu"        naabu        || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "nmap"         nmap         || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "whois"        whois        || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "dig"          dig          || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "whatweb"      whatweb      || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "theHarvester" theHarvester theharvester || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "crosslinked"  crosslinked  || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "user-scanner" user-scanner || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "gowitness"    gowitness    || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "gau"          gau          || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "ffuf"         ffuf         || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "nuclei"       nuclei       || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "wpscan"       wpscan       || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "dalfox"       dalfox       || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "katana"       katana       || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "shuffledns"   shuffledns   || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "massdns"      massdns      || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "spiderfoot"   spiderfoot   || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
print_status "recon-cli"    recon-cli    || OPTIONAL_MISSING=$((OPTIONAL_MISSING+1))
if [[ -d /usr/share/seclists/Discovery/Web-Content ]]; then
  echo -e "  ${C_DIM}SecLists${C_RESET}                      ${C_GREEN}installed${C_RESET} (ffuf wordlists auto-registered on next app start)"
else
  echo -e "  ${C_DIM}SecLists${C_RESET}                      ${C_AMBER}missing${C_RESET}"
fi
if [[ -f "$N0KOVO_DIR/n0kovo_subdomains_large.txt" ]]; then
  echo -e "  ${C_DIM}n0kovo_subdomains${C_RESET}             ${C_GREEN}installed${C_RESET} (amass/dnsx/shuffledns wordlists auto-registered on next app start)"
else
  echo -e "  ${C_DIM}n0kovo_subdomains${C_RESET}             ${C_AMBER}missing${C_RESET}"
fi
echo -e "  ${C_DIM}crt.sh, ip-geo, social-scan${C_RESET}   ${C_GREEN}no install needed${C_RESET} (plain HTTPS lookups)"
echo -e "  ${C_DIM}Shodan InternetDB${C_RESET}             ${C_GREEN}no install needed${C_RESET} (free, no key, no account)"
echo -e "  ${C_DIM}Shodan${C_RESET}                        add an API key in the app's Settings panel"
echo -e "  ${C_DIM}LeakIX${C_RESET}                        add an API key in the app's Settings panel (free account required)"

echo
if [[ $REQUIRED_MISSING -eq 0 ]]; then
  log_ok "Fast-tab tools are all in place. Run: python3 app.py"
  log_ok "Prefer the terminal? Same engine, no browser: python3 -m tui"
else
  log_err "$REQUIRED_MISSING Fast-tab tool(s) still missing — re-run this script, or install manually (see README.md)."
fi
if [[ $OPTIONAL_MISSING -gt 0 ]]; then
  log_warn "$OPTIONAL_MISSING optional tool(s) missing — those pipeline steps will just be skipped with a warning at scan time."
fi

if [[ $DRY_RUN -eq 1 ]]; then
  echo
  log "This was a dry run — nothing was actually installed or changed."
fi

[[ $REQUIRED_MISSING -eq 0 ]]
