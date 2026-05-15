#!/usr/bin/env bash
# Wildcat Finance public diagnostic scan — supply-chain attack
#
# This script is read-only. It does NOT execute, build, install, or run project
# code. It only inspects git object/reflog metadata, source file contents,
# process state, shell history, and local startup mechanisms.
#
# Usage:
#   bash scan-script.sh [search-root ...]
#
# Default search-root is $HOME. Pass one or more paths to narrow the scan.
#
# Optional environment variables:
#   SINCE="60 days ago"   git/history context window
#   MAX_RESULTS=50        per-section output limit
#   SHOW_CONTEXT=1        print trigger-command history even without code hits
#
# It looks for:
#   1) Public Wildcat malicious commit SHAs in local git object databases
#      (whether checked out or present from a prior fetch)
#   2) Recent force-update / force-push reflog entries
#   3) Exact recovered loader, blockchain dead-drop, and C2 indicators
#   4) Correlated loader patterns that are suspicious only in combination
#   5) Orphan / detached node processes that match the persistence pattern
#   6) Shell history entries for likely trigger commands, when useful
#   7) Startup and crontab entries that may indicate persistence
#
# Interpretation:
#   - CRITICAL: exact known IoC, active process/persistence match, or public
#     malicious commit that was checked out / is in HEAD.
#   - HIGH: public malicious commit in a local branch, or suspicious correlated
#     loader behavior; inspect immediately.
#   - REVIEW: useful context or heuristic signal; not proof of compromise.
#
# Output goes to stdout. Nothing is modified.

set -u

if [ "$#" -gt 0 ]; then
  ROOTS=("$@")
else
  ROOTS=("$HOME")
fi

SINCE="${SINCE:-60 days ago}"
MAX_RESULTS="${MAX_RESULTS:-50}"
SHOW_CONTEXT="${SHOW_CONTEXT:-0}"

case "$MAX_RESULTS" in
  ''|*[!0-9]*) MAX_RESULTS=50 ;;
esac

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  RED=$'\033[31m'
  YEL=$'\033[33m'
  GRN=$'\033[32m'
  DIM=$'\033[2m'
  RST=$'\033[0m'
else
  RED=''
  YEL=''
  GRN=''
  DIM=''
  RST=''
fi

CODE_HITS=0
PROCESS_HITS=0
PERSISTENCE_HITS=0
PUBLIC_MALICIOUS_COMMIT_HITS=0
PUBLIC_CONTEXT_COMMIT_HITS=0
PUBLIC_COMMIT_CRITICAL_HITS=0
PUBLIC_COMMIT_HIGH_HITS=0

# ---------------------------------------------------------------------------
# Public repository commits that downstream users could have cloned or fetched.
#
# These are intentionally limited to public Wildcat repos. Private-repo SHAs are
# not useful for neighboring orgs and are excluded from this public diagnostic.
# ---------------------------------------------------------------------------
PUBLIC_MALICIOUS_COMMITS=(
  "cab0e9f851de02a486e6213b5dda2c2008bafb89|wildcat-finance/v2-protocol|malicious hardhat.config.ts loader"
  "0fa96616c3ccc2f586b028162746fb17bacc509c|wildcat-finance/subgraph|malicious scripts/deploy.js append"
)

# ---------------------------------------------------------------------------
# Attack-window public commit useful for timeline hunting. The investigation
# found no loader in this v2-protocol commit, so it is context rather than proof
# of malicious code exposure.
# ---------------------------------------------------------------------------
PUBLIC_CONTEXT_COMMITS=(
  "54e35e0c1aa1e9f4cabcf86ac3cd68e9c119ae61|wildcat-finance/v2-protocol|attack-window force-push commit; no loader observed"
)

# ---------------------------------------------------------------------------
# Exact IoCs recovered from the known blockchain-dead-drop loader family.
#
# The 5-3-332 marker is specific to the recovered version and can change.
# ---------------------------------------------------------------------------
KNOWN_IOCS=(
  "global.i='5-3-332'"                 # recovered loader version marker
  "global['_V']='5-3-332'"             # recovered loader version marker
  "eval(\"global['_V']='5-3-332';\"+atob("  # base64 eval bootstrap
  "oWN(5586)"                          # token-substitution obfuscation marker
  "Z2xvYmFsWyJyIl09"                   # base64 for global["r"]= bootstrap code
  "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP" # TRON dead-drop account, payload 1
  "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG" # TRON dead-drop account, detached payload
  "TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v" # TRON dead-drop account, main RAT loader
  "0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e" # Aptos fallback, payload 1
  "0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3" # Aptos fallback, detached payload
  "0x533b2dbcaeff19cd1f799234a27b578d713d8fcaa341b7501e4526106483e0b1" # Aptos fallback, main RAT loader
  "0x64286dc9d288cca084d3697237ad8e22573181b5b7a3ac8f0289a0369c28b6c9" # BSC transaction, payload 1
  "0xa896af4f2876df59af1e705fb75031630ebd37fa89659a9896be4d3da8c87f02" # BSC transaction, detached payload
  "0x28069d5af130eebc8bd27ca98c005a2a32bee1c08ba59e1af216f13b18db349d" # BSC transaction, main RAT loader
  "TCqf6ZkaQD84vYsC2cuu1jRwB6JveTaRrF" # TRON dead-drop account, Next.js variant
  "TFMryB9m6d4kBMRjEVyFRbqKSV1cV2NcpH" # TRON dead-drop account, Next.js variant
  "0x9d202c824402ca89e9aaccd2390b6f8b332ae743caa1469c695feb2781d56519" # BSC transaction, Next.js variant
  "0x3d2075f97b7b1e3234bd653779d21c605d7d8c6ec9c98d983880be5c7f4f9471" # BSC transaction, Next.js variant
  "2[gWfGj;<:-93Z^C"                   # XOR key, payload 1
  "m6:tTh^D)cBz?NM]"                   # XOR key, detached payload
  "23.27.202.27"                       # Socket.IO / upload C2 host
  "198.105.127.210"                    # detached bootloader C2 host
  "166.88.54.158"                      # recovered C2/config host
)

# ---------------------------------------------------------------------------
# These are legitimate public infrastructure hosts on their own. They are only
# reported when correlated with dynamic code loading or suspicious bootstrap code.
# ---------------------------------------------------------------------------
CHAIN_HOSTS=(
  "api.trongrid.io"                    # TRON public API used by loader
  "fullnode.mainnet.aptoslabs.com"     # Aptos fallback API used by loader
  "bsc-dataseed.binance.org"           # BSC RPC used to fetch transaction input
  "bsc-rpc.publicnode.com"             # BSC RPC used to fetch transaction input
)

GLOBAL_MARKERS=(
  "global['_V']"                       # version / dedupe marker family
  "global[\"_V\"]"                     # version / dedupe marker family
  "global.i="                          # version / dedupe marker family
)

BASE64_LOADERS=(
  "atob("                              # browser-style base64 decode
  "Buffer.from("                       # Node.js decode primitive
  "base64"                             # encoding marker for decoded payloads
)

DYNAMIC_EXEC=(
  "eval("                              # direct JavaScript execution
  "Function("                          # dynamic JavaScript execution
  "child_process"                      # shell / process execution capability
)

NODE_E_PATTERNS=(
  "spawn(\"node\""                     # detached child Node process
  "spawn('node'"                       # detached child Node process
  "exec(\"node -e"                     # inline Node execution
  "exec('node -e"                      # inline Node execution
  "node -e"                            # inline Node execution
)

CREATE_REQUIRE="createRequire(import.meta.url)"

section() {
  printf '\n%s%s%s\n' "$DIM" "$1" "$RST"
}

severity() {
  case "$1" in
    CRITICAL) printf '%sCRITICAL%s' "$RED" "$RST" ;;
    HIGH) printf '%sHIGH%s' "$RED" "$RST" ;;
    REVIEW) printf '%sREVIEW%s' "$YEL" "$RST" ;;
    OK) printf '%sOK%s' "$GRN" "$RST" ;;
    *) printf '%s' "$1" ;;
  esac
}

grep_any_fixed() {
  local file="$1"
  shift
  local args=()
  local pat
  for pat in "$@"; do
    args+=("-e" "$pat")
  done
  [ "${#args[@]}" -gt 0 ] || return 1
  grep -IFq "${args[@]}" -- "$file" 2>/dev/null
}

grep_stdin_any_fixed() {
  local args=()
  local pat
  for pat in "$@"; do
    args+=("-e" "$pat")
  done
  [ "${#args[@]}" -gt 0 ] || return 1
  grep -IFq "${args[@]}" 2>/dev/null
}

grep_regex() {
  local file="$1"
  local regex="$2"
  grep -IEq "$regex" -- "$file" 2>/dev/null
}

short_pattern() {
  local pat="$1"
  if [ "${#pat}" -gt 72 ]; then
    printf '%s...' "${pat:0:72}"
  else
    printf '%s' "$pat"
  fi
}

is_entry_path() {
  case "$1" in
    */next.config.*|*/hardhat.config.*|*/vite.config.*|*/webpack.config.*|*/rollup.config.*) return 0 ;;
    */astro.config.*|*/svelte.config.*|*/nuxt.config.*|*/remix.config.*|*/postcss.config.*) return 0 ;;
    */scripts/deploy.*|*/scripts/*deploy*|*/src/index.*|*/server.*|*/package.json) return 0 ;;
    *) return 1 ;;
  esac
}

find_git_repos() {
  local root
  for root in "${ROOTS[@]}"; do
    [ -e "$root" ] || continue
    find "$root" \( -name ".git" -type d -o -name ".git" -type f \) -prune -print0 2>/dev/null
  done
}

find_code_files() {
  local root
  for root in "${ROOTS[@]}"; do
    [ -e "$root" ] || continue
    find "$root" \
      \( -type d \( -name ".git" -o -name "node_modules" -o -name ".next" -o -name "dist" -o -name "build" -o -name ".cache" -o -name ".yarn" -o -name "coverage" -o -name "artifacts" -o -name "typechain-types" \) -prune \) -o \
      \( -type f \( -name "*.js" -o -name "*.cjs" -o -name "*.mjs" -o -name "*.ts" -o -name "*.cts" -o -name "*.mts" -o -name "*.jsx" -o -name "*.tsx" -o -name "*.json" \) -print0 \) \
      2>/dev/null
  done
}

print_commit_exposure() {
  local repo="$1"
  local sha="$2"
  local exposure=''
  local local_refs=''
  local remote_refs=''
  local reflog_times=''
  local reflog_hit=''
  local ref=''

  reflog_hit="$(git -C "$repo" reflog show --format='%H' 2>/dev/null | grep -m1 "^${sha}" || true)"
  if [ -n "$reflog_hit" ]; then
    exposure='CHECKED OUT'
    reflog_times="$(
      git -C "$repo" reflog show --format='%H %ci' 2>/dev/null |
        grep "^${sha}" |
        sed "s/^${sha} //" |
        tr '\n' '; '
    )"
  elif git -C "$repo" merge-base --is-ancestor "$sha" HEAD 2>/dev/null; then
    exposure='IN HEAD'
  else
    while IFS= read -r ref; do
      [ -z "$ref" ] && continue
      case "$ref" in
        refs/remotes/*) remote_refs="${remote_refs} ${ref#refs/remotes/}" ;;
        refs/heads/*) local_refs="${local_refs} ${ref#refs/heads/}" ;;
        refs/tags/*) local_refs="${local_refs} ${ref}" ;;
        *) local_refs="${local_refs} ${ref}" ;;
      esac
    done < <(git -C "$repo" for-each-ref --format='%(refname)' --contains "$sha" 2>/dev/null)

    if [ -n "$local_refs" ]; then
      exposure='LOCAL BRANCH'
    elif [ -n "$remote_refs" ]; then
      exposure='FETCHED ONLY'
    else
      exposure='ORPHANED'
    fi
  fi

  printf '%s\n' "$exposure"
  [ -n "$local_refs" ] && printf '    local refs:%s\n' "$local_refs"
  [ -n "$remote_refs" ] && printf '    remote refs:%s\n' "$remote_refs"
  [ -n "$reflog_times" ] && printf '    reflog timestamps: %s\n' "$reflog_times"
  git -C "$repo" log -1 --format='    author=%an<%ae> committed=%ci signed=%G?' "$sha" 2>/dev/null
}

echo "${DIM}=== Wildcat public diagnostic scan ===${RST}"
printf 'Scanning roots:\n'
for root in "${ROOTS[@]}"; do
  printf '  %s\n' "$root"
done
printf 'Started: %s\n' "$(date -u +%FT%TZ)"
printf 'Git/history context since: %s\n' "$SINCE"

# ---------------------------------------------------------------------------
# 1) Find every git repo under the requested roots and check for the public
#    Wildcat malicious SHAs in its object database.
#
#    For each hit, classifies exposure level:
#      CHECKED OUT  — reflog shows the SHA was HEAD (working tree had the code)
#      IN HEAD      — SHA is ancestor of current HEAD (pulled/merged, tree has it)
#      LOCAL BRANCH — a local branch contains it (pulled but not current checkout)
#      FETCHED ONLY — only remote-tracking refs contain it (never pulled)
#      ORPHANED     — object exists but no ref reaches it
# ---------------------------------------------------------------------------
section "[1/7] Scanning local git repos for public Wildcat SHAs..."
PUBLIC_COMMIT_MATCHES=0
while IFS= read -r -d '' gitpath; do
  repo="$(dirname "$gitpath")"
  git -C "$repo" rev-parse --git-dir >/dev/null 2>&1 || continue

  for commit_record in "${PUBLIC_MALICIOUS_COMMITS[@]}" "${PUBLIC_CONTEXT_COMMITS[@]}"; do
    IFS='|' read -r sha public_repo note <<EOF
$commit_record
EOF

    if ! git -C "$repo" cat-file -e "${sha}^{commit}" 2>/dev/null; then
      continue
    fi

    PUBLIC_COMMIT_MATCHES=$((PUBLIC_COMMIT_MATCHES + 1))
    exposure_output="$(print_commit_exposure "$repo" "$sha")"
    exposure="${exposure_output%%$'\n'*}"

    commit_kind='context'
    for malicious_record in "${PUBLIC_MALICIOUS_COMMITS[@]}"; do
      if [ "$commit_record" = "$malicious_record" ]; then
        commit_kind='malicious'
        break
      fi
    done

    sev='REVIEW'
    if [ "$commit_kind" = 'malicious' ]; then
      PUBLIC_MALICIOUS_COMMIT_HITS=$((PUBLIC_MALICIOUS_COMMIT_HITS + 1))
      case "$exposure" in
        'CHECKED OUT'|'IN HEAD')
          sev='CRITICAL'
          PUBLIC_COMMIT_CRITICAL_HITS=$((PUBLIC_COMMIT_CRITICAL_HITS + 1))
          ;;
        'LOCAL BRANCH')
          sev='HIGH'
          PUBLIC_COMMIT_HIGH_HITS=$((PUBLIC_COMMIT_HIGH_HITS + 1))
          ;;
      esac
    else
      PUBLIC_CONTEXT_COMMIT_HITS=$((PUBLIC_CONTEXT_COMMIT_HITS + 1))
    fi

    printf '  %s repo=%s public_repo=%s exposure=%s\n' "$(severity "$sev")" "$repo" "$public_repo" "$exposure"
    printf '    sha=%s\n' "$sha"
    printf '    note=%s\n' "$note"
    printf '%s\n' "$exposure_output" | sed '1d'

    [ "$PUBLIC_COMMIT_MATCHES" -ge "$MAX_RESULTS" ] && {
      printf '  %s output truncated at %s public commit matches\n' "$(severity REVIEW)" "$MAX_RESULTS"
      break 2
    }
  done
done < <(find_git_repos)

if [ "$PUBLIC_COMMIT_MATCHES" -eq 0 ]; then
  printf '  %s no known public Wildcat commit objects found\n' "$(severity OK)"
else
  printf '  %s fetched-only or orphaned public commit objects are lower-risk context; checkout/HEAD hits matter most.\n' "$(severity REVIEW)"
fi

# ---------------------------------------------------------------------------
# 2) Look for recent force-update / force-push entries in git reflogs.
#    This is context only: force updates are common in some workflows, but they
#    are worth reviewing when investigating this style of attack.
# ---------------------------------------------------------------------------
section "[2/7] Scanning git reflogs for force updates..."
GIT_HITS=0
while IFS= read -r -d '' gitpath; do
  repo="$(dirname "$gitpath")"
  git -C "$repo" rev-parse --git-dir >/dev/null 2>&1 || continue

  force_lines="$(
    git -C "$repo" reflog show --all --date=iso --since="$SINCE" --format='%ci %gd %gs' 2>/dev/null |
      grep -Ei 'forced?-update|forced update|force-push|force push' |
      head -"$MAX_RESULTS" || true
  )"

  if [ -n "$force_lines" ]; then
    GIT_HITS=$((GIT_HITS + 1))
    printf '  %s repo=%s\n' "$(severity REVIEW)" "$repo"
    printf '%s\n' "$force_lines" | sed 's/^/    /'
  fi
done < <(find_git_repos)

if [ "$GIT_HITS" -eq 0 ]; then
  printf '  %s no recent force-update reflog entries found\n' "$(severity OK)"
else
  printf '  %s force updates are not proof of compromise; inspect unexpected default-branch rewrites.\n' "$(severity REVIEW)"
fi

# ---------------------------------------------------------------------------
# 3) Search file contents for exact recovered loader, dead-drop, and C2 IoCs.
#    Exact hits are high-confidence unless they are inside documentation,
#    detection rules, or malware samples being intentionally stored.
# ---------------------------------------------------------------------------
section "[3/7] Searching for exact recovered IoCs in project files..."
EXACT_HITS=0
while IFS= read -r -d '' file; do
  if grep_any_fixed "$file" "${KNOWN_IOCS[@]}"; then
    EXACT_HITS=$((EXACT_HITS + 1))
    CODE_HITS=$((CODE_HITS + 1))
    printf '  %s file=%s\n' "$(severity CRITICAL)" "$file"
    matched=0
    for pat in "${KNOWN_IOCS[@]}"; do
      if grep -IFq -e "$pat" -- "$file" 2>/dev/null; then
        matched=$((matched + 1))
        printf '    matched: %s\n' "$(short_pattern "$pat")"
        [ "$matched" -ge 5 ] && {
          printf '    ... more exact IoC strings matched\n'
          break
        }
      fi
    done
    [ "$EXACT_HITS" -ge "$MAX_RESULTS" ] && {
      printf '  %s output truncated at %s exact-hit files\n' "$(severity REVIEW)" "$MAX_RESULTS"
      break
    }
  fi
done < <(find_code_files)

if [ "$EXACT_HITS" -eq 0 ]; then
  printf '  %s no exact recovered IoCs found in scanned source files\n' "$(severity OK)"
else
  printf '  %s If this hit is inside an incident report, detection rule, or sample, treat it as documentation context.\n' "$(severity REVIEW)"
fi

# ---------------------------------------------------------------------------
# 4) Search for suspicious loader structure while avoiding noisy single-string
#    findings. Public RPC hosts, createRequire(import.meta.url), base64 helpers,
#    and child_process are not malicious by themselves.
# ---------------------------------------------------------------------------
section "[4/7] Searching for correlated loader patterns..."
HEURISTIC_HITS=0
while IFS= read -r -d '' file; do
  has_chain=0
  has_marker=0
  has_base64=0
  has_dynamic=0
  has_node_e=0
  has_create_require=0
  entry_file=0

  grep_any_fixed "$file" "${CHAIN_HOSTS[@]}" && has_chain=1
  grep_any_fixed "$file" "${GLOBAL_MARKERS[@]}" && has_marker=1
  grep_any_fixed "$file" "${BASE64_LOADERS[@]}" && has_base64=1
  grep_any_fixed "$file" "${DYNAMIC_EXEC[@]}" && has_dynamic=1
  grep_any_fixed "$file" "${NODE_E_PATTERNS[@]}" && has_node_e=1
  grep -IFq -e "$CREATE_REQUIRE" -- "$file" 2>/dev/null && has_create_require=1
  is_entry_path "$file" && entry_file=1

  reason=''
  sev=''

  if [ "$has_chain" -eq 1 ] && [ "$has_dynamic" -eq 1 ] && [ "$has_base64" -eq 1 ]; then
    sev='HIGH'
    reason='blockchain/RPC host plus dynamic base64-capable execution'
  elif [ "$has_marker" -eq 1 ] && [ "$has_dynamic" -eq 1 ] && [ "$has_base64" -eq 1 ]; then
    sev='HIGH'
    reason='global marker plus dynamic base64-capable execution'
  elif [ "$has_node_e" -eq 1 ] && { [ "$has_marker" -eq 1 ] || [ "$has_base64" -eq 1 ] || [ "$has_chain" -eq 1 ]; }; then
    sev='HIGH'
    reason='node -e child process with marker/base64/blockchain context'
  elif [ "$entry_file" -eq 1 ] && [ "$has_create_require" -eq 1 ] && [ "$has_dynamic" -eq 1 ] && [ "$has_base64" -eq 1 ]; then
    sev='REVIEW'
    reason='auto-loaded config combines createRequire with dynamic base64-capable execution'
  fi

  long_hidden_line="$(
    awk 'length($0) > 1000 && $0 ~ /(eval\(|atob\(|Function\(|child_process|spawn\(|exec\(|createRequire\(import\.meta\.url\))/ { printf "%s:%d: line length %d\n", FILENAME, FNR, length($0)); exit }' "$file" 2>/dev/null || true
  )"

  if [ -z "$reason" ] && [ "$entry_file" -eq 1 ] && [ -n "$long_hidden_line" ]; then
    sev='REVIEW'
    reason='auto-loaded file has an unusually long executable-looking line'
  fi

  if [ -n "$reason" ]; then
    HEURISTIC_HITS=$((HEURISTIC_HITS + 1))
    CODE_HITS=$((CODE_HITS + 1))
    printf '  %s file=%s\n' "$(severity "$sev")" "$file"
    printf '    reason: %s\n' "$reason"
    [ -n "$long_hidden_line" ] && printf '    %s\n' "$long_hidden_line"
    [ "$HEURISTIC_HITS" -ge "$MAX_RESULTS" ] && {
      printf '  %s output truncated at %s heuristic-hit files\n' "$(severity REVIEW)" "$MAX_RESULTS"
      break
    }
  fi
done < <(find_code_files)

if [ "$HEURISTIC_HITS" -eq 0 ]; then
  printf '  %s no correlated loader heuristics found\n' "$(severity OK)"
fi

# ---------------------------------------------------------------------------
# 5) Look for orphan / detached node processes matching the persistence pattern:
#    `node -e` with global markers, base64 decoding, RPC hosts, or process-spawn
#    indicators in the command line.
# ---------------------------------------------------------------------------
section "[5/7] Checking for malicious detached node processes..."
PS_OUT="$(ps -ef 2>/dev/null || true)"
SUSPECT_PROCS="$(
  printf '%s\n' "$PS_OUT" |
    grep -E '[n]ode[[:space:]]+-e' |
    grep -Ei 'global\[|global\.|atob\(|Buffer\.from|api\.trongrid|bsc-|socket\.io|child_process|spawn\(' || true
)"

if [ -n "$SUSPECT_PROCS" ]; then
  PROCESS_HITS=1
  printf '  %s suspicious node -e process context:\n' "$(severity CRITICAL)"
  printf '%s\n' "$SUSPECT_PROCS" | head -"$MAX_RESULTS" | sed 's/^/    /'
else
  printf '  %s no suspicious node -e process context found\n' "$(severity OK)"
fi

# ---------------------------------------------------------------------------
# 6) Shell history check — did the user run likely trigger commands?
#    This is only execution context, so it is skipped unless code indicators hit
#    or SHOW_CONTEXT=1 is set.
# ---------------------------------------------------------------------------
section "[6/7] Shell history scan for dev/build/deploy commands..."
if [ "$CODE_HITS" -eq 0 ] && [ "$PUBLIC_MALICIOUS_COMMIT_HITS" -eq 0 ] && [ "$SHOW_CONTEXT" != "1" ]; then
  printf '  %s no code indicators found; trigger-command history skipped to reduce noise\n' "$(severity OK)"
  printf '  %sset SHOW_CONTEXT=1 to print matching dev/build/deploy history anyway%s\n' "$DIM" "$RST"
else
  HIST_FOUND=0
  HIST_FILES=("$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.local/share/fish/fish_history")
  for hf in "${HIST_FILES[@]}"; do
    [ -f "$hf" ] || continue
    matches="$(
      grep -E 'next (dev|build)|p?npm (run )?(dev|build|start|deploy)|yarn (dev|build|start|deploy)|npx hardhat|pnpm hardhat|yarn hardhat|node scripts/deploy\.js|tsx src/index\.ts|ts-node src/index\.ts' "$hf" 2>/dev/null |
        tail -20 || true
    )"
    if [ -n "$matches" ]; then
      HIST_FOUND=1
      printf '  %s %s\n' "$(severity REVIEW)" "$hf"
      printf '%s\n' "$matches" | sed 's/^/    /'
    fi
  done
  [ "$HIST_FOUND" -eq 0 ] && printf '  %s no matching trigger commands found\n' "$(severity OK)"
  printf '  %shistory timestamps are shell-dependent; use this only as execution context%s\n' "$DIM" "$RST"
fi

# ---------------------------------------------------------------------------
# 7) Persistence-mechanism quick check — startup files and current-user crontab.
# ---------------------------------------------------------------------------
section "[7/7] Startup and crontab persistence check..."
STARTUP_TARGETS=(
  "$HOME/.bashrc"
  "$HOME/.bash_profile"
  "$HOME/.zshrc"
  "$HOME/.profile"
  "$HOME/.config/fish/config.fish"
  "$HOME/Library/LaunchAgents"
  "$HOME/.config/autostart"
  "$HOME/.config/systemd/user"
  "/etc/cron.d"
  "/etc/launchd.conf"
)

scan_persistence_file() {
  local file="$1"
  local found=0

  if grep_any_fixed "$file" "${KNOWN_IOCS[@]}"; then
    printf '  %s persistence file contains exact IoC: %s\n' "$(severity CRITICAL)" "$file"
    found=1
  elif grep_regex "$file" 'node[[:space:]]+-e.*(global\[|global\.|atob\(|Buffer\.from|api\.trongrid|bsc-)' ||
       grep_regex "$file" '(curl|wget).*(\||;)[[:space:]]*(sh|bash|zsh)' ||
       grep_regex "$file" 'base64[[:space:]]+(-d|--decode).*(\||;)[[:space:]]*(sh|bash|zsh)'; then
    printf '  %s suspicious persistence-like entry: %s\n' "$(severity HIGH)" "$file"
    found=1
  fi

  [ "$found" -eq 1 ]
}

for target in "${STARTUP_TARGETS[@]}"; do
  [ -e "$target" ] || continue
  if [ -d "$target" ]; then
    while IFS= read -r -d '' startup_file; do
      if scan_persistence_file "$startup_file"; then
        PERSISTENCE_HITS=$((PERSISTENCE_HITS + 1))
      fi
    done < <(find "$target" -type f -print0 2>/dev/null)
  else
    if scan_persistence_file "$target"; then
      PERSISTENCE_HITS=$((PERSISTENCE_HITS + 1))
    fi
  fi
done

CRON="$(crontab -l 2>/dev/null || true)"
if [ -n "$CRON" ]; then
  if printf '%s\n' "$CRON" | grep_stdin_any_fixed "${KNOWN_IOCS[@]}"; then
    printf '  %s current user crontab contains exact IoC\n' "$(severity CRITICAL)"
    PERSISTENCE_HITS=$((PERSISTENCE_HITS + 1))
  elif printf '%s\n' "$CRON" | grep -Ei 'node[[:space:]]+-e.*(global\[|global\.|atob\(|Buffer\.from|api\.trongrid|bsc-)|(curl|wget).*(\||;)[[:space:]]*(sh|bash|zsh)|base64[[:space:]]+(-d|--decode).*(\||;)[[:space:]]*(sh|bash|zsh)' >/dev/null 2>&1; then
    printf '  %s current user crontab has suspicious persistence-like command\n' "$(severity HIGH)"
    PERSISTENCE_HITS=$((PERSISTENCE_HITS + 1))
  fi
fi

if [ "$PERSISTENCE_HITS" -eq 0 ]; then
  printf '  %s no matching startup or crontab persistence entries found\n' "$(severity OK)"
fi

section "=== Summary ==="
printf 'Public malicious commit objects: %s\n' "$PUBLIC_MALICIOUS_COMMIT_HITS"
printf 'Public context commit objects: %s\n' "$PUBLIC_CONTEXT_COMMIT_HITS"
printf 'Exact IoC files: %s\n' "$EXACT_HITS"
printf 'Correlated loader files: %s\n' "$HEURISTIC_HITS"
printf 'Suspicious process hits: %s\n' "$PROCESS_HITS"
printf 'Persistence hits: %s\n' "$PERSISTENCE_HITS"
printf '\n'
printf 'Interpretation:\n'
printf '  [1] Public commit hits:\n'
printf '        CHECKED OUT / IN HEAD  -> malicious public repo code was in the working tree.\n'
printf '                                  Treat as compromised if the repo was built/run.\n'
printf '        LOCAL BRANCH           -> a local branch contains the malicious commit.\n'
printf '                                  Investigate whether it was checked out or run.\n'
printf '        FETCHED ONLY / ORPHANED -> lower risk, but useful evidence of exposure.\n'
printf '  [2] Force-update hits        -> context only; inspect unexpected branch rewrites.\n'
printf '  [3] Exact IoC hits           -> high-confidence unless in docs, samples, or rules.\n'
printf '  [4] Correlated loader hits   -> suspicious combinations; inspect manually.\n'
printf '  [5]-[7] Runtime/persistence  -> active process or persistence hits need immediate review.\n'
printf '\n'

if [ "$PUBLIC_COMMIT_CRITICAL_HITS" -gt 0 ] || [ "$EXACT_HITS" -gt 0 ] || [ "$PROCESS_HITS" -gt 0 ] || [ "$PERSISTENCE_HITS" -gt 0 ]; then
  printf '%s\n' "$(severity CRITICAL) Treat checked-out public malicious commits, exact IoCs, active process hits, or persistence hits as an incident unless clearly explained by documentation, samples, or detection rules."
elif [ "$PUBLIC_COMMIT_HIGH_HITS" -gt 0 ] || [ "$HEURISTIC_HITS" -gt 0 ]; then
  printf '%s\n' "$(severity HIGH) Inspect local-branch public malicious commit hits and heuristic hits manually before escalation; weak primitives alone are intentionally ignored."
elif [ "$PUBLIC_MALICIOUS_COMMIT_HITS" -gt 0 ] || [ "$PUBLIC_CONTEXT_COMMIT_HITS" -gt 0 ]; then
  printf '%s\n' "$(severity REVIEW) Public commit objects were found only as lower-risk fetched/orphaned/context hits; review whether the affected repo was ever checked out or run."
else
  printf '%s\n' "$(severity OK) No exact IoCs or correlated loader behavior found in the scanned scope."
fi

