#!/usr/bin/env bash
#
# php2shell-triage.sh
# Read-only triage for PHP2Shell (CVE-2026-109618 / CVE-2026-109619).
# It checks whether your PHP build was in the vulnerable range and looks for
# the few signals an exploitation attempt tends to leave behind.
#
# It never changes anything on the system. It only reads logs and lists files.
# Run as root (or via sudo) so it can read FPM and auth logs:
#   sudo bash php2shell-triage.sh [WEBROOT]
#
# WEBROOT is optional. If omitted, the script tries to auto-detect Laravel roots.

set -u
IFS=$'\n\t'

# ---- cosmetics -------------------------------------------------------------
if [ -t 1 ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; BOLD=$'\e[1m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; B=""; BOLD=""; N=""
fi

FINDINGS=0           # hard red flags
WARNINGS=0           # things worth a look
hr() { printf '%s\n' "------------------------------------------------------------"; }
section() { echo; printf '%s== %s ==%s\n' "$BOLD" "$1" "$N"; }
ok()    { printf '  %s[ ok ]%s %s\n' "$G" "$N" "$1"; }
warn()  { printf '  %s[warn]%s %s\n' "$Y" "$N" "$1"; WARNINGS=$((WARNINGS+1)); }
flag()  { printf '  %s[FLAG]%s %s\n' "$R" "$N" "$1"; FINDINGS=$((FINDINGS+1)); }
info()  { printf '  %s[info]%s %s\n' "$B" "$N" "$1"; }

# grep -c prints "0" AND exits 1 on no match, so "|| echo 0" would yield "0\n0".
# This helper always returns a single integer.
count() { local c; c=$("$@" 2>/dev/null); echo "${c:-0}" | tail -n1; }

printf '%sPHP2Shell triage%s  
(CVE-2026-109618 / CVE-2026-109619)\n' "$BOLD" "$N"
printf 'host: %s   date: %s\n' "$(hostname 2>/dev/null)" "$(date -u '+%Y-%m-%d %H:%M UTC')"
[ "$(id -u)" -ne 0 ] && warn "not running as root, some logs may be unreadable (re-run with sudo)"

# ---- version comparison helper ---------------------------------------------
version_lt() { # returns 0 if $1 < $2
  if command -v dpkg >/dev/null 2>&1; then
    dpkg --compare-versions "$1" lt "$2"
  else
    [ "$1" = "$2" ] && return 1
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]
  fi
}

floor_for_branch() { # patched upstream floor per branch, empty = no upstream fix
  case "$1" in
    8.5) echo "8.5.12" ;;
    8.4) echo "8.4.27" ;;
    8.3) echo "8.3.36" ;;
    8.2) echo "8.2.35" ;;
    *)   echo "" ;;
  esac
}

# =============================================================================
section "1. PHP versions (are you on a patched build?)"
# ================================
=============================================
declare -a BINS=()
for b in php php8.5 php8.4 php8.3 php8.2 php8.1 php8.0 php7.4; do
  command -v "$b" >/dev/null 2>&1 && BINS+=("$(command -v "$b")")
done
for f in /usr/sbin/php-fpm* /usr/bin/php-fpm*; do
  [ -x "$f" ] && BINS+=("$f")
done

if [ "${#BINS[@]}" -eq 0 ]; then
  warn "no php binaries found on PATH or in /usr/sbin, cannot check versions"
else
  for bin in $(printf '%s\n' "${BINS[@]}" | sort -u); do
    ver=$("$bin" -v 2>/dev/null | grep -oE 
'PHP [0-9]+\.[0-9]+\.[0-9]+' | head -n1 | awk '{print $2}')
    [ -z "$ver" ] && continue
    branch=$(echo "$ver" | cut -d. -f1,2)
    floor=$(floor_for_branch "$branch")
    label="$bin -> $ver"
    if [ -z "$floor" ]; then
      flag "$label : branch $branch has no upstream fix (EOL). Needs a backported package or an upgrade."
    elif version_lt "$ver" "$floor"; then
      flag "$label : below patched upstream build $floor (see backport note below)"
    else
      ok "$label : patched ($branch fixed in $floor)"
    fi
  done
  info "CLI and FPM can differ. The 
version that serves your site is the FPM one."
  info "Distro repos (official Debian/Ubuntu, RHEL/Alma) often backport fixes WITHOUT"
  info "bumping the upstream version. If a FLAG above comes from such a package, check:"
  info "  apt changelog php8.3-fpm | grep -E '109618|109619'      (Debian/Ubuntu)"
  info "  rpm -q --changelog php-fpm | grep -E '109618|109619'    (RHEL/Alma)"
  info "Laravel Forge uses the ondrej PPA, which follows upstream versions."
fi

# ================================
=============================================
section "2. OOM fatals in PHP/FPM logs (the exploitation trigger signature)"
# =============================================================================
# The bug is reached via a fatal error, typically 'Allowed memory size exhausted'.
# A cluster of these, especially on 2026-10-21, is the strongest single signal.
declare -a PHPLOGS=()
for p in /var/log/php*-fpm.log* /var/log/php*fpm*.log* /var/log/php_errors.log*; do
  [ -f "$p" ] && PHPLOGS+=("$p")
done
if [ "${#PHPLOGS[@]}" -eq 0 ]; then
  info "no php-fpm logs found under /var/log (check your pool error_log setting)"
else
  total=0
  for log in $(printf '%s\n' "${PHPLOGS[@]}" | sort -u); do
    case "$log" in *.gz) reader="zgrep" ;; *) reader="grep" ;; esac
    c=$(count "$reader" -c -i 'Allowed memory size' "$log")
    total=$((total + c))
    [ "$c" -gt 0 ] && info "$log : $c OOM fatal(s)"
  done
  if [ "$total" -eq 0 ]; then
    ok "no 'Allowed memory size' fatals in php-fpm logs"
  elif [ "$total" -le 3 ]; then
    warn "$total OOM fatal(s) total, 
review the surrounding lines manually"
  else
    flag "$total OOM fatal(s) total, this matches the PHP2Shell trigger pattern, investigate"
  fi
fi

# =============================================================================
section "3. POST volume in web access logs"
# =============================================================================
# Standard access logs do NOT record Content-Type, so the multipart trigger is
# not directly visible. This is a low-signal lead, nothing more.
declare -a ACCESS=()
for a in /var/log/nginx/*access*.log /var/log/apache2/*access*.log; do
  [ -f "$a" ] && ACCESS+=("$a")
done
if [ "${#ACCESS[@]}" -eq 0 ]; then
  info "no access logs found in the usual spots, skipping"
  info "Note: Laravel Forge site configs often ship with 'access_log off'."
else
  for log in "${ACCESS[@]}"; do
    posts=$(count grep -c '"POST ' "$log")
    oct21=$(count sh -c "grep '21/Oct/2026' \"\$1\" | grep -c '\"POST '" _ "$log")
    info "$log : $posts POST total, $oct21 of them on 2026-10-21"
    [ "$posts" -eq 0 ] && info "  0 POSTs 
usually means per-site logging is off (Forge default: 'access_log off')"
  done
  info "top POST targets on 2026-10-21 (look for endpoints that never take uploads):"
  for log in "${ACCESS[@]}"; do
    grep '21/Oct/2026' "$log" 2>/dev/null | grep '"POST ' \
      | awk '{print $7}' | sort | uniq -c | sort -rn | head -10 \
      | sed 's/^/      /'
  done
fi

# =============================================================================
section "4. Unexpected file changes in webroot"
# =============================================================================
declare -a ROOTS=()
if [ -n "${1:-}" ] && [ -d "${1:-}" ]; then
  ROOTS+=("$1")
else
  for cand in /home/forge/*/current /home/forge/* /var/www/* /var/www; do
    [ -f "$cand/artisan" ] && ROOTS+=("$cand")
  done
fi
if [ "${#ROOTS[@]}" -eq 0 ]; then
  info "no Laravel webroot auto-detected, pass one as the first argument"
else
  for root in $(printf '%s\n' 
"${ROOTS[@]}" | sort -u); do
    info "scanning $root"
    # Zero-downtime deploys (Forge, Envoyer, Deployer) create a fresh release
    # directory on every deploy, so "changed since date X" would list the whole
    # app after a deploy. For a release dir, compare against the release itself:
    # anything modified AFTER the release was created is suspicious.
    real=$(readlink -f "$root")
    if [ -d "$root/.git" ]; then
      info "git checkout found, relying on git status below instead of file times"
    else
      case "$real" in
        */releases/*) ref_args=(-newer "$real"); ref_label="after this release 
was deployed" ;;
        *)            ref_args=(-newermt '2026-10-20'); ref_label="since 2026-10-20" ;;
      esac
      recent=$(find "$real" -name '*.php' "${ref_args[@]}" \
               -not -path '*/vendor/*' -not -path '*/node_modules/*' \
               -not -path '*/storage/framework/*' -not -path '*/bootstrap/cache/*' 2>/dev/null)
      if [ -n "$recent" ]; then
        warn "PHP files changed $ref_label (review each):"
        echo "$recent" | sed 's/^/        /'
      else
        ok "no app PHP files changed $ref_label"
      fi
    fi
    # PHP files where they should never be (public/, storage/)
    odd=$(find "$root/public" "$root/storage" -name '*.php' \
          -not -path "$root/public/index.php" -not -path '*/framework/views/*' \
          -not -path '*/storage/framework/maintenance.php' 2>/dev/null)
    if [ -n "$odd" ]; then
      flag "PHP files in public/ or storage/ besides index.php (review each):"
      echo "$odd" | sed 's/^/        /'
    else
      ok "no stray PHP files in public/ or storage/"
    fi
    # if it is a git checkout, the diff is the cleanest truth
    if [ -d "$root/.git" ]; then
      # ignore .env, storage (a symlink to shared storage on Forge) and caches
      dirty=$(git -C "$root" status --porcelain 2>/dev/null \
              | grep -vE '\.env$| storage(/|$)| bootstrap/cache/')
      if [ -n "$dirty" ]; then
        warn "git working tree has unexpected changes in $root:"
        echo "$dirty" | sed 's/^/        /'
      else
        ok "git working tree clean (ignoring .env, storage, cache)"
      fi
    fi
  done
fi

# ================================
=============================================
section "5. Persistence leftovers"
# =============================================================================
info "cron entries (review for anything you did not set up):"
for c in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
  [ -f "$c" ] && echo "      $c"
done

akcount=0
for ak in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  if [ -f "$ak" ]; then
    n=$(count grep -c . "$ak")
    akcount=$((akcount+1))
    info "$ak : $n key(s)"
  fi
done
if [ "$akcount" -eq 0 ]; then
  info "no authorized_keys files found"
else
  warn "verify every SSH key above is one you recognise"
fi

if [ -f /var/log/auth.log ]; then
  recent_logins=$(grep -i 'Accepted' /var/log/auth.log 2>/dev/null | tail -10)
  if [ -n "$recent_logins" ]; then
    info "recent successful SSH logins (tail):"
    echo "$recent_logins" | sed 's/^/      /'
    info "On Forge, logins as root/forge from DigitalOcean ranges are usually Forge itself."
    info "Compare against https://forge
.laravel.com/ips-v4.txt"
  fi
fi

if command -v ss >/dev/null 2>&1; then
  # skip loopback, common service ports and inbound SSH sessions (listed above)
  est=$(ss -tunp 2>/dev/null | grep -i estab \
        | grep -vE '127\.0\.0\.1|\[::1\]|:443 |:80 |:5432 |:3306 |:6379 ' \
        | grep -v '(("sshd"')
  if [ -n "$est" ]; then
    warn "established connections on non-standard ports (check for odd outbound):"
    echo "$est" | sed 's/^/      /'
  else
    ok "no established connections on 
non-standard ports"
  fi
fi

# =============================================================================
section "Verdict"
# =============================================================================
hr
if [ "$FINDINGS" -gt 0 ]; then
  printf '%s%d flag(s) and %d warning(s).%s\n' "$R$BOLD" "$FINDINGS" "$WARNINGS" "$N"
  echo "Treat this host as suspect. The patch does not undo a prior compromise."
  echo "Review each FLAG, preserve 
logs, and rotate secrets"
  echo "(APP_KEY, DB credentials, API keys, origin TLS keys)."
elif [ "$WARNINGS" -gt 0 ]; then
  printf '%s0 flags, %d warning(s).%s\n' "$Y$BOLD" "$WARNINGS" "$N"
  echo "No strong sign of compromise. Clear the warnings above before you relax."
else
  printf '%sClean: 0 flags, 0 warnings.%s\n' "$G$BOLD" "$N"
  echo "No signal of prior exploitation from the checks this script can do."
fi
hr
echo "Limits: the memory-disclosure variant leaks data into a response cookie and"
echo "leaves almost no trace on disk. 
A real zero-day window existed, so rotating"
echo "sensitive secrets is cheap insurance regardless of the result above."