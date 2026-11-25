#!/usr/bin/env bash
# Assemble all TLS/NetCom objects in the four library variants (syntax/macro check only).
# Usage: assemble_tls.sh <output dir> [repo root]
# Writes only into <output dir>; OBJASM_PATH is set to the repo root for the assembler.
set -u
OUT="${1:?output directory required}"
RF="${2:-$(cd "$(dirname "$0")/../../../.." && pwd)}"          # repo root (forward slashes)
R="$(cygpath -w "$RF" 2>/dev/null || echo "$RF")"               # Windows form for OBJASM_PATH
OBJECTS="NetCom TLS_CertValidator TLS_CertProvider TLS_ClientCertProvider TLS_ServerCertProvider \
TLS_Context TLS_DefaultCertValidator TLS_DefaultClientCertProvider TLS_DefaultServerCertProvider \
TLS_SChannelContext"
FAIL=0
for v in 64W 64A 32W 32A; do
  bits=${v:0:2}
  [ "${v:2:1}" = W ] && str=WIDE_STRING || str=ANSI_STRING
  mkdir -p "$OUT/$v"
  printf '%% include @Environ(OBJASM_PATH)\\Code\\Macros\\Model.inc\r\nSysSetup OOP, LIB%s, %s\r\n' \
         "$bits" "$str" > "$OUT/$v/Objects.cop"
  ( cd "$OUT/$v" || exit 1
    rm -f ./*.obj ./*.out ./*.err
    for o in $OBJECTS; do
      OBJASM_PATH="$R" "$RF/Build/Tools/Assembler/UASM$bits.exe" \
        @"$RF/Build/Options/OPT_ASM_LIB_$bits.txt" "$RF/Code/Objects/$o.asm" > "$o.out" 2>&1
      if grep -qi 'error a' "$o.out" || [ ! -f "$o.obj" ]; then
        echo "[$v] $o FAILED:"; grep -i 'error' "$o.out" | head -5
        exit 2
      fi
    done ) || FAIL=1
  echo "[$v] $(ls "$OUT/$v"/*.obj 2>/dev/null | wc -l) objects assembled"
done
exit $FAIL
