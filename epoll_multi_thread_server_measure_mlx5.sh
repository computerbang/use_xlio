#!/usr/bin/env bash
# server_multicore_measure.sh
#
# 목적
# - 멀티코어(멀티 워커) 서버 전송 실험에서 "요청 처리 구간(윈도우)"만 정확히 잘라 CPU 시간을 측정한다.
#
# 측정 윈도우 정의 (start/end)
# - 시작: 서버 로그에서 "MEASURE_BEGIN" 라인이 처음 관측되는 시점
#          (= 서버가 응답 송신 상태에 실제 진입한 순간)
# - 종료: 서버 로그에서 "MEASURE_END" 라인이 RUN_REQUESTS개 관측되는 시점
#          (= 요청이 모두 전송 완료된 순간)
#
# 시간값은 스크립트가 date로 재지 않고, 서버가 출력한 t_ns=... 값을 사용한다.
#
# s/GB(또는 s/GiB) 분모(denominator)
# - /proc/net/dev TX 바이트가 아닌, "실제 페이로드 바이트"를 분모로 사용한다.
#   = FILE_TO_GET(요청 1회당 파일 크기) × RUN_REQUESTS(요청 횟수)
# - /proc/net/dev의 TX 바이트는 헤더/재전송 등 영향이 포함될 수 있어 참고값으로만 출력한다.

set -euo pipefail

# 사용자 설정 변수
VERBOSE=${VERBOSE:-1}
ALLOW_SW_FALLBACK=${ALLOW_SW_FALLBACK:-0}
CPUSET=${CPUSET:-0}
IRQ_CPUSET=${IRQ_CPUSET:-$CPUSET}
IFACE=${IFACE:-enp161s0f1np1}
SERVER_BIN=${SERVER_BIN:-/usr/local/src/performance_measurement_script/multi_thread_server/epoll/use_xlio/http_server_v2.0}
CERT=${CERT:-/etc/ssl/certs/nginx_cert.pem}
KEY=${KEY:-/etc/ssl/private/nginx_key.pem}
BASEDIR=${BASEDIR:-/data}
PORT=${PORT:-4613}
MODE=${MODE:-OPENSSL}
WORKERS=${WORKERS:-1}
PIN_NUMA=${PIN_NUMA:-1}
SET_RSS=${SET_RSS:-1}
RSS_QUEUES=${RSS_QUEUES:-1}
SET_RPS_XPS=${SET_RPS_XPS:-1}
PIN_IRQ=${PIN_IRQ:-1}
USE_CGROUP=${USE_CGROUP:-1}

SNDBUF="${SNDBUF:-0}"
NOTSENT_LOWAT="${NOTSENT_LOWAT:-0}"

# XLIO on/off
USE_XLIO=${USE_XLIO:-0}              # 0: off, 1: on
XLIO_LIB=${XLIO_LIB:-libxlio.so}     # 필요시 절대경로 지정 가능
XLIO_UTLS_TX=${XLIO_UTLS_TX:-1}
XLIO_UTLS_RX=${XLIO_UTLS_RX:-1}
XLIO_TRACELEVEL=${XLIO_TRACELEVEL:-2} # 0: none, 1: error, 2: info, 3: debug
XLIO_HANDLE_SIGSEGV=${XLIO_HANDLE_SIGSEGV:-1}
XLIO_LOG_FILE=${XLIO_LOG_FILE:-}
XLIO_STATS_FILE=${XLIO_STATS_FILE:-}

# 요청 관련 설정
FILE_TO_GET=${FILE_TO_GET:-1G}
RUN_REQUESTS=${RUN_REQUESTS:-1}

# 측정 종료 후 서버를 종료할지 여부
KILL_SERVER_ON_DONE=${KILL_SERVER_ON_DONE:-0}

SS_SAMPLE_ENABLE=${SS_SAMPLE_ENABLE:-1}
SS_SAMPLE_INTERVAL=${SS_SAMPLE_INTERVAL:-0.25}
SS_FILTER_PORT=${SS_FILTER_PORT:-$PORT}

# 내부 상수/경로
TS=$(date +%Y%m%d_%H%M%S)
WORKDIR="${WORKDIR:-/usr/local/src/performance_measurement_script/multi_thread_server/epoll/use_xlio/ss_cpu_${TS}}"
LOGFILE="${WORKDIR}/server.log"
PERF_ENABLE=${PERF_ENABLE:-0}
PERF_MODE=${PERF_MODE:-stat}   # stat | record
PERF_TARGET=${PERF_TARGET:-pid}
PERF_EVENTS=${PERF_EVENTS:-cycles,instructions,cache-references,cache-misses,branches,branch-misses,context-switches,cpu-migrations,page-faults}
PERF_OUT=${PERF_OUT:-${WORKDIR}/perf.stat}
PERF_RECORD_OUT=${PERF_RECORD_OUT:-${WORKDIR}/perf.data}
PERF_REPORT_OUT=${PERF_REPORT_OUT:-${WORKDIR}/perf.report.txt}
PERF_LOG=${PERF_LOG:-${WORKDIR}/perf.log}
PERF_PID=""
WORKER_TID=""
SYSBK="${WORKDIR}/sys_backup"
CG="/sys/fs/cgroup/ktls_xfer_${TS}"
mkdir -p "${WORKDIR}" "${SYSBK}"

# ============================================================================
# CPU 관련 함수
# ============================================================================

to_cpulist() { awk -v cpuspec="$1" '
  BEGIN{
    n = split(cpuspec, a, ",");
    for(i = 1; i <= n; i++){
      if(a[i] ~ /-/){
        split(a[i], b, "-");
        for(c = b[1]; c <= b[2]; c++) print c;
      } else print a[i];
    }
  }'
}

validate_cpuspec_or_die() {
  local spec="$1" name="$2"
  if [[ ! "$spec" =~ ^[0-9,-]+$ ]]; then
    echo "[ERR] bad ${name}: ${spec}"
    exit 1
  fi
}

cpuspec_to_listcsv() {
  local spec="$1"
  to_cpulist "$spec" | tr '\n' ',' | sed 's/,$//'
}

mask_from_cpulist(){ python3 - "$1" <<'PY'
import sys
cpus = [int(x) for x in sys.argv[1].split(',') if x!='']
m = 0
for c in cpus: m |= (1<<c)
print("{:x}".format(m))
PY
}

# ============================================================================
# 크기/포맷 변환 함수
# ============================================================================

CLK_TCK=$(getconf CLK_TCK)
BYTES_PER_GIB=$((1024*1024*1024))

parse_size_bytes(){ python3 - "$1" <<'PY'
import sys
s = sys.argv[1].strip().upper()
mul = {'K':1024,'M':1024**2,'G':1024**3,'T':1024**4}
print(int(float(s[:-1]) * mul[s[-1]]) if s[-1] in mul else int(s))
PY
}

gi(){ awk -v B="$1" -v G="$BYTES_PER_GIB" 'BEGIN{printf "%.3f", (B > 0) ? B/G : 0.0}'; }

S2GB(){ awk -v s="$1" -v B="$2" -v GiB="$BYTES_PER_GIB" 'BEGIN{if(B > 0){printf "%.6f", s/(B/GiB)} else{printf "0.000000"} }'; }

# ============================================================================
# /proc 시스템 정보 함수
# ============================================================================

read_proc_stat_line(){ awk -v id="$1" '$1==id{print; exit}' /proc/stat; }

extract_irq_soft(){ awk '{print $(7), $(8)}' <<<"$1"; }

read_tx_bytes(){ awk -v dev="$IFACE" '$1==dev":"{print $10}' /proc/net/dev 2>/dev/null | tr -d ' '; }

# ============================================================================
# ss -tin 샘플링/요약 (4개 지표만)
# ============================================================================

ss_dump_one() {
  ss -tin "sport = :${SS_FILTER_PORT}" 2>/dev/null \
    | awk '
      /ESTAB/ {estab=1; next}
      estab && /rwnd_limited:|snd_wnd:|delivery_rate|sndbuf_limited:/ {
        print
        exit
      }'
}

parse_ss_field_value() {
  local key="$1"
  local line="$2"
  awk -v k="$key" '
    {
      for (i = 1; i <= NF; i++) {
        if ($i == k ":" || $i == k) {
          v = $(i+1)
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
          gsub(/bps$/, "", v)
          gsub(/ms$/, "", v)
          print v
          exit
        }
        if ($i ~ ("^" k ":")) {
          v = $i
          sub("^" k ":", "", v)
          gsub(/bps$/, "", v)
          gsub(/ms$/, "", v)
          print v
          exit
        }
      }
    }' <<< "$line"
}

parse_ss_field_pct() {
  local key="$1"
  local line="$2"
  sed -n "s/.*${key}:[^)]*(\\([0-9.]*\\)%).*/\\1/p" <<< "$line" | head -n1
}

ss_sample_loop() {
  local outfile="$1"
  : > "$outfile"

  while :; do
    local ts line
    ts=$(date +%s.%N)
    line="$(ss_dump_one || true)"

    if [[ -n "$line" ]]; then
      local rwnd_ms rwnd_pct snd_wnd delivery_rate sndbuf_ms sndbuf_pct

      rwnd_ms=$(parse_ss_field_value "rwnd_limited" "$line")
      rwnd_pct=$(parse_ss_field_pct   "rwnd_limited" "$line")
      snd_wnd=$(parse_ss_field_value  "snd_wnd" "$line")
      delivery_rate=$(parse_ss_field_value "delivery_rate" "$line")
      sndbuf_ms=$(parse_ss_field_value "sndbuf_limited" "$line")
      sndbuf_pct=$(parse_ss_field_pct   "sndbuf_limited" "$line")

      printf "%s %s %s %s %s %s %s\n" \
        "${ts}" \
        "${rwnd_ms:-0}" \
        "${rwnd_pct:-0}" \
        "${snd_wnd:-0}" \
        "${delivery_rate:-0}" \
        "${sndbuf_ms:-0}" \
        "${sndbuf_pct:-0}" >> "$outfile"
    fi

    sleep "$SS_SAMPLE_INTERVAL"
  done
}

ss_calc_summary() {
  local infile="$1"

  if [[ ! -s "$infile" ]]; then
    SS_SAMPLES=0

    SS_RWND_MS_LAST=0
    SS_RWND_PCT_LAST=0
    SS_RWND_MS_MAX=0
    SS_RWND_PCT_MAX=0
    SS_RWND_MS_AVG=0
    SS_RWND_PCT_AVG=0

    SS_SND_WND_LAST=0
    SS_SND_WND_MIN=0
    SS_SND_WND_MAX=0
    SS_SND_WND_AVG=0

    SS_DELIVERY_RATE_LAST=0
    SS_DELIVERY_RATE_MIN=0
    SS_DELIVERY_RATE_MAX=0
    SS_DELIVERY_RATE_AVG=0
    SS_DELIVERY_RATE_NZAVG=0

    SS_SNDBUF_MS_LAST=0
    SS_SNDBUF_PCT_LAST=0
    SS_SNDBUF_MS_MAX=0
    SS_SNDBUF_PCT_MAX=0
    SS_SNDBUF_MS_AVG=0
    SS_SNDBUF_PCT_AVG=0
    return 0
  fi

  read \
    SS_SAMPLES \
    SS_RWND_MS_LAST SS_RWND_PCT_LAST SS_RWND_MS_MAX SS_RWND_PCT_MAX SS_RWND_MS_AVG SS_RWND_PCT_AVG \
    SS_SND_WND_LAST SS_SND_WND_MIN SS_SND_WND_MAX SS_SND_WND_AVG \
    SS_DELIVERY_RATE_LAST SS_DELIVERY_RATE_MIN SS_DELIVERY_RATE_MAX SS_DELIVERY_RATE_AVG SS_DELIVERY_RATE_NZAVG \
    SS_SNDBUF_MS_LAST SS_SNDBUF_PCT_LAST SS_SNDBUF_MS_MAX SS_SNDBUF_PCT_MAX SS_SNDBUF_MS_AVG SS_SNDBUF_PCT_AVG \
  < <(
    awk '
      BEGIN{
        n=0
        rwnd_ms_sum=0; rwnd_pct_sum=0
        snd_wnd_sum=0
        delivery_sum=0; delivery_nz_sum=0; delivery_nz_cnt=0
        sndbuf_ms_sum=0; sndbuf_pct_sum=0

        rwnd_ms_max=0; rwnd_pct_max=0
        snd_wnd_min=-1; snd_wnd_max=0
        delivery_min=-1; delivery_max=0
        sndbuf_ms_max=0; sndbuf_pct_max=0
      }
      {
        n++

        rwnd_ms=$2+0
        rwnd_pct=$3+0
        snd_wnd=$4+0
        delivery=$5+0
        sndbuf_ms=$6+0
        sndbuf_pct=$7+0

        last_rwnd_ms=rwnd_ms
        last_rwnd_pct=rwnd_pct
        last_snd_wnd=snd_wnd
        last_delivery=delivery
        last_sndbuf_ms=sndbuf_ms
        last_sndbuf_pct=sndbuf_pct

        rwnd_ms_sum += rwnd_ms
        rwnd_pct_sum += rwnd_pct
        snd_wnd_sum += snd_wnd
        delivery_sum += delivery
        sndbuf_ms_sum += sndbuf_ms
        sndbuf_pct_sum += sndbuf_pct

        if (delivery > 0) {
          delivery_nz_sum += delivery
          delivery_nz_cnt++
        }

        if (rwnd_ms > rwnd_ms_max) rwnd_ms_max=rwnd_ms
        if (rwnd_pct > rwnd_pct_max) rwnd_pct_max=rwnd_pct

        if (snd_wnd_min < 0 || snd_wnd < snd_wnd_min) snd_wnd_min=snd_wnd
        if (snd_wnd > snd_wnd_max) snd_wnd_max=snd_wnd

        if (delivery_min < 0 || delivery < delivery_min) delivery_min=delivery
        if (delivery > delivery_max) delivery_max=delivery

        if (sndbuf_ms > sndbuf_ms_max) sndbuf_ms_max=sndbuf_ms
        if (sndbuf_pct > sndbuf_pct_max) sndbuf_pct_max=sndbuf_pct
      }
      END{
        if (n == 0) {
          printf "0 "
          for (i=0;i<21;i++) printf "0 "
          printf "\n"
          exit
        }

        delivery_nzavg = (delivery_nz_cnt > 0) ? (delivery_nz_sum / delivery_nz_cnt) : 0

        printf "%d ", n

        printf "%.0f %.1f %.0f %.1f %.3f %.3f ", \
          last_rwnd_ms, last_rwnd_pct, rwnd_ms_max, rwnd_pct_max, rwnd_ms_sum/n, rwnd_pct_sum/n

        printf "%.0f %.0f %.0f %.3f ", \
          last_snd_wnd, snd_wnd_min, snd_wnd_max, snd_wnd_sum/n

        printf "%.0f %.0f %.0f %.3f %.3f ", \
          last_delivery, delivery_min, delivery_max, delivery_sum/n, delivery_nzavg

        printf "%.0f %.1f %.0f %.1f %.3f %.3f\n", \
          last_sndbuf_ms, last_sndbuf_pct, sndbuf_ms_max, sndbuf_pct_max, sndbuf_ms_sum/n, sndbuf_pct_sum/n
      }' "$infile"
  )
}

# ============================================================================
# 설정 파싱 및 변수 초기화
# ============================================================================

validate_cpuspec_or_die "$CPUSET" "CPUSET"
CPULIST=$(cpuspec_to_listcsv "$CPUSET")
CPU_ARR=($(echo "$CPULIST" | tr ',' ' '))
NCPU=${#CPU_ARR[@]}

IRQ_CPUSET=${IRQ_CPUSET:-$CPUSET}
validate_cpuspec_or_die "$IRQ_CPUSET" "IRQ_CPUSET"
IRQ_CPULIST=$(cpuspec_to_listcsv "$IRQ_CPUSET")
IRQ_CPU_ARR=($(echo "$IRQ_CPULIST" | tr ',' ' '))
NIRQCPU=${#IRQ_CPU_ARR[@]}

MON_CPULIST=$(
  printf "%s\n%s\n" "$CPULIST" "$IRQ_CPULIST" \
  | tr ',' '\n' \
  | awk 'NF{ if (!seen[$1]++) print $1 }' \
  | sort -n \
  | tr '\n' ',' \
  | sed 's/,$//'
)
MON_CPU_ARR=($(echo "$MON_CPULIST" | tr ',' ' '))
NMONCPU=${#MON_CPU_ARR[@]}

[[ -z "$WORKERS" ]] && WORKERS=$NCPU
[[ -z "${RSS_QUEUES}" ]] && RSS_QUEUES=$NCPU

FILE_BYTES=$(parse_size_bytes "$FILE_TO_GET")
PAYLOAD_BYTES=$(( FILE_BYTES * RUN_REQUESTS ))

# ============================================================================
# cgroup v2 관련 함수
# ============================================================================

cg_create(){ [[ "${USE_CGROUP}" = "1" ]] || return 0; mkdir -p "$CG"; }

cg_add(){ [[ "${USE_CGROUP}" = "1" ]] || return 0; echo "$1" > "$CG/cgroup.procs" 2>/dev/null || true; }

cg_read_cpu_stat(){
  [[ "${USE_CGROUP}" = "1" ]] || { echo "0 0 0"; return 0; }
  awk '{a[$1]=$2} END{print a["usage_usec"]+0, a["user_usec"]+0, a["system_usec"]+0}' "$CG/cpu.stat"
}

cg_cleanup(){ [[ "${USE_CGROUP}" = "1" ]] || return 0; rmdir "$CG" 2>/dev/null || true; }

# ============================================================================
# irqbalance 제어 함수
# ============================================================================

stop_irqbalance(){ systemctl stop irqbalance 2>/dev/null || true; echo "[INFO] irqbalance stopped"; }

restore_irqbalance(){ systemctl start irqbalance 2>/dev/null || true; echo "[CLEANUP] irqbalance started"; }

# ============================================================================
# ethtool 및 RSS 큐 관리 함수
# ============================================================================

have_ethtool(){ command -v ethtool >/dev/null 2>&1; }

get_preset_max(){
  have_ethtool || { echo ""; return 0; }
  ethtool -l "$IFACE" 2>/dev/null | awk '/Pre-set maximums:/{f=1;next} f&&$1=="Combined:"{print $2;exit}'
}

get_current_combined(){
  have_ethtool || { echo ""; return 0; }
  ethtool -l "$IFACE" 2>/dev/null | awk '/Current hardware settings:/{f=1;next} f&&$1=="Combined:"{print $2;exit}'
}

verify_queues(){ local want="$1"; local cur="$(get_current_combined || true)"; [[ "$cur" == "$want" ]]; }

shrink_to_n(){
  local want="$1"
  local preset
  local orig="${SYSBK}/preset_queues"

  preset="$(get_preset_max || true)"
  [[ -n "$preset" ]] && echo "$preset" > "$orig" || echo "unknown" > "$orig"

  if have_ethtool; then
    ethtool -L "$IFACE" combined "$want" >/dev/null 2>&1 || true
    sleep 0.2

    if verify_queues "$want"; then
      echo "[INFO] ${IFACE}: queues set to ${want}"
    else
      echo "[WARN] queues set may need link flap"
    fi
  fi
}

restore_queues(){
  local orig="${SYSBK}/preset_queues"

  [[ -f "$orig" ]] || { echo "[CLEANUP] no queue backup"; return 0; }

  local target
  target="$(cat "$orig")"

  [[ "$target" == "unknown" || -z "$target" ]] && { echo "[CLEANUP] queue restore skipped"; return 0; }

  local cur
  cur="$(get_current_combined || true)"

  [[ "$cur" == "$target" ]] && { echo "[CLEANUP] queues already ${target}"; return 0; }

  have_ethtool && ethtool -L "$IFACE" combined "$target" >/dev/null 2>&1 || true
  sleep 0.2

  if verify_queues "$target"; then
    echo "[CLEANUP] queues restored: ${cur:-?} -> ${target}"
  else
    echo "[CLEANUP][NEEDS-FLAP] ip link set $IFACE down && ethtool -L $IFACE combined $target && ip link set $IFACE up"
  fi
}

# ============================================================================
# RPS/XPS 관리 함수
# ============================================================================

set_rps_xps(){
  local qdir="/sys/class/net/${IFACE}/queues"
  [[ -d "$qdir" ]] || return 0

  mkdir -p "${SYSBK}/rps" "${SYSBK}/xps"

  local mask_hex
  mask_hex=$(mask_from_cpulist "$IRQ_CPULIST")

  for f in "$qdir"/rx-*/rps_cpus; do
    [[ -f "$f" ]] && {
      cp "$f" "${SYSBK}/rps/$(basename "$(dirname "$f")")" 2>/dev/null || true
      echo "$mask_hex" > "$f" 2>/dev/null || true
    }
  done

  for f in "$qdir"/tx-*/xps_cpus; do
    [[ -f "$f" ]] && {
      cp "$f" "${SYSBK}/xps/$(basename "$(dirname "$f")")" 2>/dev/null || true
      echo "$mask_hex" > "$f" 2>/dev/null || true
    }
  done

  echo "[INFO] RPS/XPS set to IRQ_CPUSET=${IRQ_CPUSET} (mask=0x${mask_hex})"
}

restore_rps_xps(){
  local qdir="/sys/class/net/${IFACE}/queues"

  if [[ -d "${SYSBK}/rps" ]]; then
    for f in "${SYSBK}"/rps/*; do
      local q
      q=$(basename "$f")
      [[ -f "$qdir/$q/rps_cpus" ]] && cat "$f" > "$qdir/$q/rps_cpus" || true
    done
    echo "[CLEANUP] RPS restored"
  fi

  if [[ -d "${SYSBK}/xps" ]]; then
    for f in "${SYSBK}"/xps/*; do
      local q
      q=$(basename "$f")
      [[ -f "$qdir/$q/xps_cpus" ]] && cat "$f" > "$qdir/$q/xps_cpus" || true
    done
    echo "[CLEANUP] XPS restored"
  fi
}

# ============================================================================
# IRQ affinity 관리 함수 (mlx5_comp 중심)
# ============================================================================

pci_bdf_of_iface() {
  readlink -f "/sys/class/net/${IFACE}/device" | awk -F/ '{print $NF}'
}

collect_irqs() {
  local bdf
  bdf="$(pci_bdf_of_iface)"

  [[ -n "$bdf" ]] || return 0

  awk -v pat="$bdf" '
    /^[ 0-9]+:/ {
      gsub(":", "", $1); irq=$1
      if (index($0, pat) && index($0, "mlx5_comp") ) print irq
    }' /proc/interrupts \
    | sort -n \
    | head -n "${RSS_QUEUES:-1}"
}

affine_irqs_round_robin(){
  local irqs=($(collect_irqs))

  ((${#irqs[@]})) || { echo "[INFO] No IRQs for ${IFACE}"; return 0; }

  local idx=0
  for irq in "${irqs[@]}"; do
    [[ -f "/proc/irq/${irq}/smp_affinity_list" ]] || continue

    cat "/proc/irq/${irq}/smp_affinity_list" > "${SYSBK}/irq_${irq}.aff" 2>/dev/null || true

    local cpu="${IRQ_CPU_ARR[$((idx % NIRQCPU))]}"
    echo "$cpu" > "/proc/irq/${irq}/smp_affinity_list" 2>/dev/null || true

    echo "[INFO] IRQ ${irq} -> CPU ${cpu}"

    idx=$((idx + 1))
  done

  printf "%s\n" "${irqs[@]}" > "${SYSBK}/irq_list.txt"
}

restore_irq_aff(){
  [[ -f "${SYSBK}/irq_list.txt" ]] || return 0

  while read -r irq; do
    [[ -f "/proc/irq/${irq}/smp_affinity_list" && -f "${SYSBK}/irq_${irq}.aff" ]] && \
      cat "${SYSBK}/irq_${irq}.aff" > "/proc/irq/${irq}/smp_affinity_list" || true
  done < "${SYSBK}/irq_list.txt"

  echo "[CLEANUP] IRQ smp_affinity_list restored"
}

# ============================================================================
# perf helper 함수
# ============================================================================

find_worker_tid(){
  local spid="$1" cpu="$2" tid=""
  for _ in $(seq 1 30); do
    tid="$(ps -T -p "$spid" -o tid=,psr=,pcpu=,comm= 2>/dev/null \
      | awk -v pid="$spid" -v cpu="$cpu" '$1 != pid && $2 == cpu { print $1, $3 }' \
      | sort -k2,2nr \
      | awk 'NR==1{print $1}')"
    [[ -n "$tid" ]] && { echo "$tid"; return 0; }
    sleep 0.1
  done
  return 1
}

start_perf(){
  [[ "${PERF_ENABLE}" = "1" ]] || return 0
  local target_tid=""
  if [[ "${PERF_TARGET}" = "worker" ]]; then
    target_tid="$(find_worker_tid "$SERVER_PID" "$CPUSET" || true)"
  else
    target_tid="$SERVER_PID"
  fi

  if [[ -z "$target_tid" ]]; then
    echo "[WARN] PERF target tid not found" | tee -a "$LOGFILE"
    return 0
  fi

  WORKER_TID="$target_tid"
  : > "$PERF_LOG"

  if [[ "${PERF_MODE}" = "record" ]]; then
    rm -f "$PERF_RECORD_OUT" "$PERF_REPORT_OUT"
    setsid perf record -g -t "$WORKER_TID" -o "$PERF_RECORD_OUT" >"$PERF_LOG" 2>&1 &
    PERF_PID=$!
    echo "[INFO] PERF(record) pid=${PERF_PID} target_tid=${WORKER_TID}" | tee -a "$LOGFILE"
  else
    rm -f "$PERF_OUT"
    setsid perf stat -x, -e "$PERF_EVENTS" -p "$WORKER_TID" -o "$PERF_OUT" -- sleep 1000 >"$PERF_LOG" 2>&1 &
    PERF_PID=$!
    echo "[INFO] PERF(stat) pid=${PERF_PID} target_tid=${WORKER_TID}" | tee -a "$LOGFILE"
  fi
}

stop_perf(){
  [[ -n "${PERF_PID:-}" ]] || return 0

  kill -INT -- "-${PERF_PID}" 2>/dev/null || true
  for _ in 1 2 3 4 5; do
    if ! kill -0 "$PERF_PID" 2>/dev/null; then
      break
    fi
    sleep 0.2
  done

  if kill -0 "$PERF_PID" 2>/dev/null; then
    kill -TERM -- "-${PERF_PID}" 2>/dev/null || true
    sleep 0.5
  fi

  if kill -0 "$PERF_PID" 2>/dev/null; then
    kill -KILL -- "-${PERF_PID}" 2>/dev/null || true
  fi

  wait "$PERF_PID" 2>/dev/null || true

  if [[ "${PERF_ENABLE}" = "1" && "${PERF_MODE}" = "record" && -f "$PERF_RECORD_OUT" ]]; then
    perf report -i "$PERF_RECORD_OUT" --stdio --sort comm,dso,symbol > "$PERF_REPORT_OUT" 2>>"$PERF_LOG" || true
  fi

  PERF_PID=""
}

# ============================================================================
# 종료 시 복구 함수
# ============================================================================

cleanup(){
  stop_perf
  restore_irq_aff
  restore_queues
  restore_rps_xps
  restore_irqbalance
  cg_cleanup
}
trap cleanup EXIT

# ============================================================================
# 측정 구간 모니터링 함수
# ============================================================================

extract_t_ns(){
  sed -n 's/.* t_ns=\([0-9]\+\).*/\1/p' <<< "$1"
}

wait_measure_window(){
  local begin_need="${1:-1}"
  local end_need="${2:-$RUN_REQUESTS}"

  local begin_seen=0
  local end_seen=0
  local started=0

  : > "${WORKDIR}/measure.window"

  (
    tail -n0 -F "$LOGFILE" 2>/dev/null & echo $! > "${WORKDIR}/tail.pid"
  ) | while read -r line; do
    echo "$line" >> "${WORKDIR}/measure.window"

    if [[ "$line" =~ ^MEASURE_BEGIN[[:space:]] ]]; then
      (( ++begin_seen ))

      if (( started == 0 && begin_seen >= begin_need )); then
        tns="$(extract_t_ns "$line")"
        [[ -n "$tns" ]] && echo "$tns" > "${WORKDIR}/t0_ns"

        cg_read_cpu_stat > "${WORKDIR}/cg0.stat"

        if [[ "${SS_SAMPLE_ENABLE}" = "1" ]]; then
          ss_sample_loop "${WORKDIR}/ss.samples" &
          echo $! > "${WORKDIR}/ss.pid"
        fi

        started=1
      fi
    fi

    if [[ "$line" =~ ^MEASURE_END[[:space:]] ]]; then
      (( ++end_seen ))

      if (( started == 1 && end_seen >= end_need )); then
        tns="$(extract_t_ns "$line")"
        [[ -n "$tns" ]] && echo "$tns" > "${WORKDIR}/t1_ns"

        cg_read_cpu_stat > "${WORKDIR}/cg1.stat"

        if [[ "${SS_SAMPLE_ENABLE}" = "1" ]]; then
          sspid=$(cat "${WORKDIR}/ss.pid" 2>/dev/null || echo "")
          [[ -n "$sspid" ]] && kill "$sspid" 2>/dev/null || true
          wait "$sspid" 2>/dev/null || true
        fi

        tailpid=$(cat "${WORKDIR}/tail.pid" 2>/dev/null || echo "")
        [[ -n "$tailpid" ]] && kill "$tailpid" 2>/dev/null || true
        break
      fi
    fi
  done
}

# ============================================================================
# 메인 실행 로직
# ============================================================================

echo "[INFO] IFACE=$IFACE  CPUSET=$CPUSET (NCPU=$NCPU)  IRQ_CPUSET=$IRQ_CPUSET (NIRQCPU=$NIRQCPU)  WORKERS=$WORKERS"
stop_irqbalance
[[ "${SET_RSS}" = "1" ]] && shrink_to_n "${RSS_QUEUES}"
[[ "${PIN_IRQ}" = "1" ]] && affine_irqs_round_robin
[[ "${SET_RPS_XPS}" = "1" ]] && set_rps_xps

# 서버 실행
CMD_PREFIX=()
if [[ -n "${PIN_NUMA}" && -x "$(command -v numactl)" ]]; then
  CMD_PREFIX+=(numactl --cpunodebind="${PIN_NUMA}" --membind="${PIN_NUMA}")
fi
if [[ -n "$CPUSET" ]]; then
  CMD_PREFIX+=(taskset -c "$CPUSET")
fi

XLIO_ENV=()
if [[ "${USE_XLIO}" = "1" ]]; then
  XLIO_ENV+=(LD_PRELOAD="${XLIO_LIB}")
  XLIO_ENV+=(XLIO_UTLS_TX="${XLIO_UTLS_TX}")
  XLIO_ENV+=(XLIO_UTLS_RX="${XLIO_UTLS_RX}")
  XLIO_ENV+=(XLIO_TRACELEVEL="${XLIO_TRACELEVEL}")
  XLIO_ENV+=(XLIO_HANDLE_SIGSEGV="${XLIO_HANDLE_SIGSEGV}")
  [[ -n "${XLIO_LOG_FILE}" ]]   && XLIO_ENV+=(XLIO_LOG_FILE="${XLIO_LOG_FILE}")
  [[ -n "${XLIO_STATS_FILE}" ]] && XLIO_ENV+=(XLIO_STATS_FILE="${XLIO_STATS_FILE}")
fi

echo "[INFO] USE_XLIO=${USE_XLIO} XLIO_LIB=${XLIO_LIB}"

if [[ "${USE_XLIO}" = "1" ]]; then
  echo "[INFO] Launch(XLIO=ON): SNDBUF=${SNDBUF:-0} NOTSENT_LOWAT=${NOTSENT_LOWAT:-0} ${XLIO_ENV[*]} ${CMD_PREFIX[*]} $SERVER_BIN $PORT $MODE $CERT $KEY $BASEDIR $WORKERS"
  env "${XLIO_ENV[@]}" \
    stdbuf -oL -eL "${CMD_PREFIX[@]}" \
    "$SERVER_BIN" "$PORT" "$MODE" "$CERT" "$KEY" "$BASEDIR" "$WORKERS" \
    >"${LOGFILE}" 2>&1 & SERVER_PID=$!
else
  echo "[INFO] Launch(XLIO=OFF): SNDBUF=${SNDBUF:-0} NOTSENT_LOWAT=${NOTSENT_LOWAT:-0} ${CMD_PREFIX[*]} $SERVER_BIN $PORT $MODE $CERT $KEY $BASEDIR $WORKERS"
  stdbuf -oL -eL "${CMD_PREFIX[@]}" \
    "$SERVER_BIN" "$PORT" "$MODE" "$CERT" "$KEY" "$BASEDIR" "$WORKERS" \
    >"${LOGFILE}" 2>&1 & SERVER_PID=$!
fi

cg_create
cg_add "$SERVER_PID"

start_perf

declare -A S0_IRQ S0_SIRQ
for c in "${MON_CPU_ARR[@]}"; do
  line=$(read_proc_stat_line "cpu${c}")
  read hi so < <(extract_irq_soft "$line")
  S0_IRQ[$c]=$hi
  S0_SIRQ[$c]=$so
done

declare -A KSOFT0_NS KSOFT1_NS
while read -r pid psr comm; do
  [[ "$comm" =~ ^ksoftirqd/([0-9]+)$ ]] || continue
  n="${BASH_REMATCH[1]}"
  [[ ",$MON_CPULIST," == *",$n,"* ]] || continue
  KSOFT0_NS[$n]=$(awk '{print $1}' "/proc/$pid/schedstat" 2>/dev/null || echo 0)
done < <(ps -eLo pid,psr,comm)

TX_START=$(read_tx_bytes)

wait_measure_window 1 "$RUN_REQUESTS"

stop_perf

if [[ "${SS_SAMPLE_ENABLE}" = "1" ]]; then
  ss_calc_summary "${WORKDIR}/ss.samples"
else
  SS_SAMPLES=0

  SS_RWND_MS_LAST=0
  SS_RWND_PCT_LAST=0
  SS_RWND_MS_MAX=0
  SS_RWND_PCT_MAX=0
  SS_RWND_MS_AVG=0
  SS_RWND_PCT_AVG=0

  SS_SND_WND_LAST=0
  SS_SND_WND_MIN=0
  SS_SND_WND_MAX=0
  SS_SND_WND_AVG=0

  SS_DELIVERY_RATE_LAST=0
  SS_DELIVERY_RATE_MIN=0
  SS_DELIVERY_RATE_MAX=0
  SS_DELIVERY_RATE_AVG=0
  SS_DELIVERY_RATE_NZAVG=0

  SS_SNDBUF_MS_LAST=0
  SS_SNDBUF_PCT_LAST=0
  SS_SNDBUF_MS_MAX=0
  SS_SNDBUF_PCT_MAX=0
  SS_SNDBUF_MS_AVG=0
  SS_SNDBUF_PCT_AVG=0
fi

[[ -s "${WORKDIR}/t0_ns" ]] || { echo "[ERR] no MEASURE_BEGIN observed"; exit 1; }
[[ -s "${WORKDIR}/t1_ns" ]] || { echo "[ERR] no MEASURE_END observed"; exit 1; }

T0=$(cat "${WORKDIR}/t0_ns")
T1=$(cat "${WORKDIR}/t1_ns")

read CG_U0 CG_USER0 CG_SYS0 < "${WORKDIR}/cg0.stat"
read CG_U1 CG_USER1 CG_SYS1 < "${WORKDIR}/cg1.stat"

TX_END=$(read_tx_bytes)

REQ_WINDOW=$(awk -v a="$T0" -v b="$T1" 'BEGIN{printf "%.3f",(b-a)/1e9}')

declare -A S1_IRQ S1_SIRQ
for c in "${MON_CPU_ARR[@]}"; do
  line=$(read_proc_stat_line "cpu${c}")
  read hi so < <(extract_irq_soft "$line")
  S1_IRQ[$c]=$hi
  S1_SIRQ[$c]=$so
done

while read -r pid psr comm; do
  [[ "$comm" =~ ^ksoftirqd/([0-9]+)$ ]] || continue
  n="${BASH_REMATCH[1]}"
  [[ ",$MON_CPULIST," == *",$n,"* ]] || continue
  KSOFT1_NS[$n]=$(awk '{print $1}' "/proc/$pid/schedstat" 2>/dev/null || echo 0)
done < <(ps -eLo pid,psr,comm)

if [[ "${KILL_SERVER_ON_DONE}" = "1" ]]; then
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
fi

irq_core_irq=0
irq_core_sirq=0
for c in "${IRQ_CPU_ARR[@]}"; do
  echo "[DEBUG] CPU $c: IRQ(${S0_IRQ[$c]} → ${S1_IRQ[$c]}), softirq(${S0_SIRQ[$c]} → ${S1_SIRQ[$c]})" >&2
  irq_core_irq=$(awk -v s="$irq_core_irq" -v a="${S0_IRQ[$c]}"  -v b="${S1_IRQ[$c]}"  -v hz="$CLK_TCK" 'BEGIN{printf "%.6f", s+ (b-a)/hz}')
  irq_core_sirq=$(awk -v s="$irq_core_sirq" -v a="${S0_SIRQ[$c]}" -v b="${S1_SIRQ[$c]}" -v hz="$CLK_TCK" 'BEGIN{printf "%.6f", s+ (b-a)/hz}')
done

app_core_irq=0
app_core_sirq=0
for c in "${CPU_ARR[@]}"; do
  echo "[DEBUG] CPU $c: IRQ(${S0_IRQ[$c]} → ${S1_IRQ[$c]}), softirq(${S0_SIRQ[$c]} → ${S1_SIRQ[$c]})" >&2
  app_core_irq=$(awk -v s="$app_core_irq" -v a="${S0_IRQ[$c]}"  -v b="${S1_IRQ[$c]}"  -v hz="$CLK_TCK" 'BEGIN{printf "%.6f", s+ (b-a)/hz}')
  app_core_sirq=$(awk -v s="$app_core_sirq" -v a="${S0_SIRQ[$c]}" -v b="${S1_SIRQ[$c]}" -v hz="$CLK_TCK" 'BEGIN{printf "%.6f", s+ (b-a)/hz}')
done

sum_irq=$(awk -v a="$irq_core_irq" -v b="$app_core_irq" 'BEGIN{printf "%.6f", a+b}')
sum_sirq=$(awk -v a="$irq_core_sirq" -v b="$app_core_sirq" 'BEGIN{printf "%.6f", a+b}')

irq_ksum=0
for n in "${IRQ_CPU_ARR[@]}"; do
  k0="${KSOFT0_NS[$n]:-0}"
  k1="${KSOFT1_NS[$n]:-0}"
  irq_ksum=$(awk -v s="$irq_ksum" -v a="$k0" -v b="$k1" 'BEGIN{printf "%.6f", s+ (b-a)/1e9}')
done

app_ksum=0
for n in "${CPU_ARR[@]}"; do
  k0="${KSOFT0_NS[$n]:-0}"
  k1="${KSOFT1_NS[$n]:-0}"
  app_ksum=$(awk -v s="$app_ksum" -v a="$k0" -v b="$k1" 'BEGIN{printf "%.6f", s+ (b-a)/1e9}')
done

ksum=$(awk -v a="$irq_ksum" -v b="$app_ksum" 'BEGIN{printf "%.6f", a+b}')
sirq_inline=$(awk -v so="$sum_sirq" -v kr="$ksum" 'BEGIN{d=so-kr; if(d<0)d=0; printf "%.6f", d;}')

if [[ "${USE_CGROUP}" = "1" ]]; then
  CG_TOT=$(awk -v a="$CG_U0"    -v b="$CG_U1"    'BEGIN{printf "%.6f",(b-a)/1e6}')
  CG_USER=$(awk -v a="$CG_USER0" -v b="$CG_USER1" 'BEGIN{printf "%.6f",(b-a)/1e6}')
  CG_SYS=$(awk -v a="$CG_SYS0"  -v b="$CG_SYS1"  'BEGIN{printf "%.6f",(b-a)/1e6}')
else
  CG_TOT=0; CG_USER=0; CG_SYS=0
fi

TX_BYTES=$(( TX_END - TX_START ))
TOTAL_TRUE=$(awk -v s="$CG_TOT" -v so="$sum_sirq" -v hi="$sum_irq" 'BEGIN{printf "%.6f", s+so+hi}')

echo
printf "=== CPU Time (완료-윈도우 | CPUSET=%s, IRQ_CPUSET=%s) ===\n" "$CPUSET" "$IRQ_CPUSET"
printf "Payload(bytes)   : %d  (%.3f GiB)\n" "$PAYLOAD_BYTES" "$(gi "$PAYLOAD_BYTES")"
printf "TX observed      : %d  (%.3f GiB)   # 참고용\n" "$TX_BYTES"      "$(gi "$TX_BYTES")"
printf "Window(sec)      : %.3f\n\n" "${REQ_WINDOW:-0}"

printf "# App (cgroup v2, 전체 스레드)\n"
printf "cgroup total     : %.3f s   → %.3f s/GB(payload)\n" "$CG_TOT"  "$(S2GB "$CG_TOT" "$PAYLOAD_BYTES")"
printf "  user/system    : %.3f / %.3f s\n\n" "$CG_USER" "$CG_SYS"

printf "# Kernel Interrupt Breakdown\n"
printf "\n[IRQ Core: CPU %s]\n" "$IRQ_CPULIST"
printf "  hardirq        : %.3f s   → %.3f s/GB(payload)\n" "$irq_core_irq"  "$(S2GB "$irq_core_irq" "$PAYLOAD_BYTES")"
printf "  softirq(total) : %.3f s   → %.3f s/GB(payload)\n" "$irq_core_sirq" "$(S2GB "$irq_core_sirq" "$PAYLOAD_BYTES")"
printf "    ├─ ksoftirqd : %.3f s   → %.3f s/GB(payload)\n" "$irq_ksum"      "$(S2GB "$irq_ksum" "$PAYLOAD_BYTES")"
printf "    └─ inline    : %.3f s\n" "$(awk -v so="$irq_core_sirq" -v kr="$irq_ksum" 'BEGIN{d=so-kr; if(d<0)d=0; printf "%.3f", d;}')"

printf "\n[App Core: CPU %s]\n" "$CPULIST"
printf "  hardirq        : %.3f s   → %.3f s/GB(payload)\n" "$app_core_irq"  "$(S2GB "$app_core_irq" "$PAYLOAD_BYTES")"
printf "  softirq(total) : %.3f s   → %.3f s/GB(payload)\n" "$app_core_sirq" "$(S2GB "$app_core_sirq" "$PAYLOAD_BYTES")"
printf "    ├─ ksoftirqd : %.3f s   → %.3f s/GB(payload)\n" "$app_ksum"      "$(S2GB "$app_ksum" "$PAYLOAD_BYTES")"
printf "    └─ inline    : %.3f s\n" "$(awk -v so="$app_core_sirq" -v kr="$app_ksum" 'BEGIN{d=so-kr; if(d<0)d=0; printf "%.3f", d;}')"

printf "\n[Total: CPUSET ∪ IRQ_CPUSET]\n"
printf "  hardirq        : %.3f s   → %.3f s/GB(payload)\n" "$sum_irq"       "$(S2GB "$sum_irq" "$PAYLOAD_BYTES")"
printf "  softirq(total) : %.3f s   → %.3f s/GB(payload)\n" "$sum_sirq"      "$(S2GB "$sum_sirq" "$PAYLOAD_BYTES")"
printf "    ├─ ksoftirqd : %.3f s   → %.3f s/GB(payload)\n" "$ksum"          "$(S2GB "$ksum" "$PAYLOAD_BYTES")"
printf "    └─ inline    : %.3f s   → %.3f s/GB(payload)\n\n" "$sirq_inline"   "$(S2GB "$sirq_inline" "$PAYLOAD_BYTES")"

printf "# Combined (중복 카운트 없음)\n"
printf "TOTAL (App+soft+IRQ): %.3f s  → %.3f s/GB(payload)\n" "$TOTAL_TRUE" "$(S2GB "$TOTAL_TRUE" "$PAYLOAD_BYTES")"
if [[ -n "${REQ_WINDOW:-}" && "${REQ_WINDOW}" != "0" ]]; then
  printf "CPU vs wall          : %.1f %%  (TOTAL / WINDOW)\n" \
    "$(awk -v t="$TOTAL_TRUE" -v w="$REQ_WINDOW" 'BEGIN{if(w>0)print 100*t/w; else print 0;}')"
fi

printf "\n# TCP flow-control snapshot (ss -tin, sampled)\n"
printf "samples                 : %s\n" "$SS_SAMPLES"

printf "\n[rwnd_limited]\n"
printf "last_ms                 : %s ms\n" "$SS_RWND_MS_LAST"
printf "last_pct                : %s %%\n" "$SS_RWND_PCT_LAST"
printf "max_ms                  : %s ms\n" "$SS_RWND_MS_MAX"
printf "max_pct                 : %s %%\n" "$SS_RWND_PCT_MAX"
printf "avg_ms                  : %s ms\n" "$SS_RWND_MS_AVG"
printf "avg_pct                 : %s %%\n" "$SS_RWND_PCT_AVG"

printf "\n[snd_wnd]\n"
printf "last                    : %s bytes\n" "$SS_SND_WND_LAST"
printf "min                     : %s bytes\n" "$SS_SND_WND_MIN"
printf "max                     : %s bytes\n" "$SS_SND_WND_MAX"
printf "avg                     : %s bytes\n" "$SS_SND_WND_AVG"

printf "\n[delivery_rate]\n"
printf "last                    : %s bps\n" "$SS_DELIVERY_RATE_LAST"
printf "max                     : %s bps\n" "$SS_DELIVERY_RATE_MAX"
printf "avg                     : %s bps\n" "$SS_DELIVERY_RATE_AVG"
printf "avg_nonzero             : %s bps\n" "$SS_DELIVERY_RATE_NZAVG"

printf "\n[sndbuf_limited]\n"
printf "last_ms                 : %s ms\n" "$SS_SNDBUF_MS_LAST"
printf "last_pct                : %s %%\n" "$SS_SNDBUF_PCT_LAST"
printf "max_ms                  : %s ms\n" "$SS_SNDBUF_MS_MAX"
printf "max_pct                 : %s %%\n" "$SS_SNDBUF_PCT_MAX"
printf "avg_ms                  : %s ms\n" "$SS_SNDBUF_MS_AVG"
printf "avg_pct                 : %s %%\n" "$SS_SNDBUF_PCT_AVG"

exit 0