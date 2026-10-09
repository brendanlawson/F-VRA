#!/usr/bin/env bash
# Best-effort install of each project's pinned dependency closure into an isolated
# Linux venv (uv venv --seed so pip exists for Snyk's introspection), then run
# Snyk Open Source (SCA) against the actually-installed set (via pip freeze).
# Same requirements.pinned.txt source that osv-scanner consumed -> cross-tool parity.
set -u
export UV_LINK_MODE=copy
INV=/inv
OUT=/out
WORK=/work
mkdir -p "$OUT/json" "$OUT/logs" "$WORK"
SUMMARY="$OUT/summary.csv"
RUNLOG="$OUT/run.log"
echo "project,pinned,gpu_excluded,installed,install_fail,snyk_exit,vulns,critical,high,medium,low,status" > "$SUMMARY"
: > "$RUNLOG"

log(){ echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$RUNLOG"; }

snyk --version >> "$RUNLOG" 2>&1 || true
snyk whoami --experimental >> "$RUNLOG" 2>&1 || true

projects=$(ls "$INV" | grep -vE '^(_scans|tools|README\.md|master_inventory\.csv|summary\.csv)$' | sort)
total=$(echo "$projects" | wc -l)
log "START snyk-pip-linux over $total projects"

for p in $projects; do
  req="$INV/$p/requirements.pinned.txt"
  plog="$OUT/logs/$p.log"
  jp="$OUT/json/$p.json"
  : > "$plog"
  rm -f "$jp"
  if [ ! -f "$req" ]; then
    echo "$p,0,0,0,0,,,,,,,no-pinned-file" >> "$SUMMARY"
    log "SKIP $p (no requirements.pinned.txt)"
    continue
  fi

  # Clean name==version list (drop --hash continuation lines and ; markers).
  clean="$WORK/$p.clean.txt"
  grep -oE '^[A-Za-z0-9][A-Za-z0-9._-]*==[^ ;\\]+' "$req" | sort -u > "$clean"
  pinned=$(wc -l < "$clean")

  # Exclude giant GPU/ML binary wheels (hundreds of MB, ~never in Snyk's vuln DB).
  # Install-based SCA must download wheels; these would cost GBs/hours for no vuln signal.
  EXCL='^(nvidia[-_].*|torch|torchvision|torchaudio|triton|pytorch[-_].*|tensorflow.*|tf-nightly.*|jax|jaxlib|onnxruntime.*|cupy.*|xformers|deepspeed|flash[-_]attn.*|bitsandbytes|nvidia.*|cudnn.*|cuda.*|nccl.*|cublas.*|cufft.*|curand.*|cusolver.*|cusparse.*|cusparselt.*|nvjitlink.*|nvtx.*|paddlepaddle.*|mkl|intel-openmp)=='
  filt="$WORK/$p.filt.txt"
  grep -ivE "$EXCL" "$clean" > "$filt"
  excluded=$(( pinned - $(wc -l < "$filt") ))
  log ">>> $p ($pinned pinned, $excluded gpu/ml excluded)"

  rm -rf /venv
  uv venv --seed /venv -p 3.12 >> "$plog" 2>&1
  export VIRTUAL_ENV=/venv

  inst_fail=0
  # 12-min cap on the whole install phase so one slow project can't stall the batch.
  if timeout 720 uv pip install --no-deps --only-binary=:all: -r "$filt" >> "$plog" 2>&1; then
    echo "ONE_SHOT_INSTALL_OK" >> "$plog"
  else
    echo "ONE_SHOT_FAILED/TIMEOUT -> per-line tolerant install" >> "$plog"
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      if ! timeout 90 uv pip install --no-deps --only-binary=:all: "$line" >> "$plog" 2>&1; then
        inst_fail=$((inst_fail+1)); echo "FAIL_INSTALL $line" >> "$plog"
      fi
    done < "$filt"
  fi

  # Snapshot what actually installed (exclude the seed tooling for parity with osv).
  wd="$WORK/$p"; mkdir -p "$wd"
  /venv/bin/pip freeze 2>/dev/null | grep -ivE '^(pip|setuptools|wheel|distribute|pkg-resources)==' > "$wd/requirements.txt"
  installed=$(wc -l < "$wd/requirements.txt")

  code=3; v=0; c=0; h=0; m=0; l=0
  if [ "$installed" -gt 0 ]; then
    ( cd "$wd" && snyk test --file=requirements.txt --command=/venv/bin/python \
        --package-manager=pip --skip-unresolved --json-file-output="$jp" >> "$plog" 2>&1 )
    code=$?
    if [ -f "$jp" ]; then
      read v c h m l < <(jq -r '
        (if type=="array" then . else [.] end)
        | [.[]|select(.vulnerabilities)|.vulnerabilities[]] as $vs
        | [ ($vs|length),
            ([$vs[]|select(.severity=="critical")]|length),
            ([$vs[]|select(.severity=="high")]|length),
            ([$vs[]|select(.severity=="medium")]|length),
            ([$vs[]|select(.severity=="low")]|length) ] | @tsv' "$jp" 2>/dev/null)
      [ -z "$v" ] && v=0; [ -z "$c" ] && c=0; [ -z "$h" ] && h=0; [ -z "$m" ] && m=0; [ -z "$l" ] && l=0
    fi
  fi

  case $code in
    0) status="clean";;
    1) status="vulns";;
    2) status="snyk-error";;
    3) status="no-install";;
    *) status="exit$code";;
  esac
  echo "$p,$pinned,$excluded,$installed,$inst_fail,$code,$v,$c,$h,$m,$l,$status" >> "$SUMMARY"
  log "<<< $p installed=$installed/$pinned snyk_exit=$code vulns=$v ($status)"
  rm -rf "$wd" "$clean"
done

log "DONE"
