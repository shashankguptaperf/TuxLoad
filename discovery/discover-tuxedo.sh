#!/bin/sh
# TuxLoad read-only discovery for a Unix or AIX Tuxedo server, or a Unix client host.
# It does not change the machine and does not log on to the Tuxedo domain.
#
# Usage:
#   sh discover-tuxedo.sh
#   sh discover-tuxedo.sh /path/to/client/app
#   sh discover-tuxedo.sh /path/to/client/app /tmp/tuxload-discovery-server.txt
#
# Run this on the Tuxedo server with the Tuxedo account so TUXDIR is already set.
# Copy the report file back. It contains host names and file paths.

APP_DIR=
OUT=./tuxload-discovery-server.txt
if [ -n "$1" ]; then
  APP_DIR=$1
fi
if [ -n "$2" ]; then
  OUT=$2
fi

BODY=/tmp/tuxload-discovery-body.$$
HOMES=/tmp/tuxload-discovery-homes.$$
STRINGS=/tmp/tuxload-discovery-strings.$$
: > "$BODY"
: > "$HOMES"
trap 'rm -f "$BODY" "$HOMES" "$STRINGS"' EXIT INT TERM

add_home() {
  h=$1
  if [ -z "$h" ] || [ ! -d "$h" ]; then
    return
  fi
  case "$h" in
    */bin|*/lib) h=`dirname "$h"` ;;
  esac
  if [ -f "$h/bin/tmadmin" ] || [ -f "$h/bin/tmboot" ] || [ -f "$h/bin/libtux.so" ] || [ -f "$h/lib/libtux.so" ] || \
     [ -f "$h/bin/libtux.a" ] || [ -f "$h/lib/libtux.a" ] || [ -f "$h/bin/libwsc.so" ] || [ -f "$h/lib/libwsc.so" ] || \
     [ -f "$h/bin/libwsc.a" ] || [ -f "$h/lib/libwsc.a" ]; then
    grep -F -x "$h" "$HOMES" >/dev/null 2>&1 || printf '%s\n' "$h" >> "$HOMES"
  fi
}

bitness_of() {
  f=$1
  if ! command -v file >/dev/null 2>&1; then
    printf '%s\n' "unknown"
    return
  fi
  desc=`file -b "$f" 2>/dev/null`
  case "$desc" in
    *64-bit*) printf '%s\n' "64-bit" ;;
    *32-bit*) printf '%s\n' "32-bit" ;;
    *) printf '%s\n' "unknown" ;;
  esac
}

printf '%s\n' "Collecting Tuxedo server facts (read-only)."

if [ -n "$TUXDIR" ]; then
  add_home "$TUXDIR"
fi

for root in /opt /opt/oracle /opt/bea /bea /usr/bea /oracle /tux /usr/local /app /apps; do
  if [ ! -d "$root" ]; then
    continue
  fi
  add_home "$root"
  for d in "$root"/* "$root"/*/*; do
    if [ ! -d "$d" ]; then
      continue
    fi
    base=`basename "$d"`
    case "$base" in
      *[Tt]uxedo*|*[Jj]olt*|*[Bb]ea*) add_home "$d" ;;
    esac
  done
done

os_name=`uname -s 2>/dev/null`
os_release=`uname -r 2>/dev/null`
os_machine=`uname -m 2>/dev/null`
aix_level=
if command -v oslevel >/dev/null 2>&1; then
  aix_level=`oslevel -s 2>/dev/null`
fi
host_name=`uname -n 2>/dev/null`

install_count=0
wsc64=0
wsc32=0
tux64=0
version_line="unknown"
if [ -s "$HOMES" ]; then
  while IFS= read -r home; do
    [ -n "$home" ] || continue
    install_count=`expr "$install_count" + 1`
    printf '\n%s\n' "Install: $home" >> "$BODY"
    if [ -x "$home/bin/tmadmin" ]; then
      ver=`"$home/bin/tmadmin" -v 2>&1 | head -n 8`
      printf '%s\n' "$ver" >> "$BODY"
      if [ "$version_line" = "unknown" ] && [ -n "$ver" ]; then
        version_line=$ver
      fi
    else
      printf '%s\n' "tmadmin: not executable" >> "$BODY"
    fi
    for dir in "$home/bin" "$home/lib"; do
      [ -d "$dir" ] || continue
      for f in "$dir"/libwsc.so "$dir"/libwsc.a "$dir"/libtux.so "$dir"/libtux.a \
               "$dir"/libfml32.so "$dir"/libfml32.a "$dir"/libengine.so "$dir"/libengine.a \
               "$dir"/libtux.dll "$dir"/libwsc.dll; do
        [ -f "$f" ] || continue
        bits=`bitness_of "$f"`
        printf '%s\n' "Library: $f ($bits)" >> "$BODY"
        base=`basename "$f"`
        case "$base" in
          libwsc.so|libwsc.a|libwsc.dll)
            if [ "$bits" = "64-bit" ]; then wsc64=`expr "$wsc64" + 1`; fi
            if [ "$bits" = "32-bit" ]; then wsc32=`expr "$wsc32" + 1`; fi
            ;;
          libtux.so|libtux.a|libtux.dll)
            if [ "$bits" = "64-bit" ]; then tux64=`expr "$tux64" + 1`; fi
            ;;
        esac
      done
    done
  done < "$HOMES"
fi

field_count=0
field_dirs=
if [ -n "$FLDTBLDIR32" ]; then
  field_dirs=$FLDTBLDIR32
  old_ifs=$IFS
  IFS=:
  for dir in $FLDTBLDIR32; do
    [ -d "$dir" ] || continue
    for f in "$dir"/*.fml32; do
      [ -f "$f" ] || continue
      field_count=`expr "$field_count" + 1`
      if [ "$field_count" -le 30 ]; then
        printf '%s\n' "Field table: $f" >> "$BODY"
      fi
    done
  done
  IFS=$old_ifs
fi

view_state="not set"
if [ -n "$VIEWDIR32" ] || [ -n "$VIEWFILES32" ]; then
  view_state="VIEW32 variables are set"
fi

client_mode="not determined"
if [ -n "$WSNADDR" ]; then
  client_mode="Workstation"
elif [ -n "$TUXCONFIG" ]; then
  client_mode="Native"
fi
if [ -n "$TOBJADDR" ]; then
  client_mode="$client_mode; CORBA"
fi

token_line="not scanned"
if [ -n "$APP_DIR" ] && [ -d "$APP_DIR" ]; then
  token_line="none"
  hits=" "
  scanned=0
  for f in "$APP_DIR"/* "$APP_DIR"/bin/* "$APP_DIR"/lib/*; do
    [ -f "$f" ] || continue
    scanned=`expr "$scanned" + 1`
    if [ "$scanned" -gt 40 ]; then
      break
    fi
    if ! command -v strings >/dev/null 2>&1; then
      token_line="strings command is not installed"
      break
    fi
    strings -a -n 5 "$f" > "$STRINGS" 2>/dev/null
    for tok in tpcall tpacall tpgetrply tpconnect tpsend tprecv tpbegin tpcommit tpabort tpenqueue tpdequeue Fadd32 FML32 libwsc libtux VIEW32; do
      if grep -F -q "$tok" "$STRINGS" 2>/dev/null; then
        case "$hits" in
          *" $tok "*) ;;
          *) hits="$hits$tok " ;;
        esac
      fi
    done
  done
  if [ "$token_line" != "strings command is not installed" ]; then
    token_line=$hits
  fi
  if echo "$hits" | grep -F -q "libwsc"; then
    client_mode="Workstation"
  fi
  printf '\n%s\n' "Application tokens:$hits" >> "$BODY"
fi

replay="not ready - no Tuxedo client libraries were found"
if [ "$wsc64" -gt 0 ]; then
  replay="64-bit Workstation library is present on this host"
elif [ "$tux64" -gt 0 ]; then
  replay="64-bit native library is present; libwsc was not found"
elif [ "$wsc32" -gt 0 ]; then
  replay="only 32-bit Workstation libraries were found"
fi

{
  printf '%s\n' "TuxLoad discovery (server)"
  printf '%s\n' "Script: discover-tuxedo.sh 0.1.0"
  printf '%s\n' "Collected: `date`"
  printf '%s\n' "Computer: $host_name"
  printf '%s\n' "Read-only: yes"
  printf '\n%s\n' "Answer 1 - Tuxedo version and operating system"
  printf '%s\n' "  Operating system: $os_name $os_release $os_machine"
  if [ -n "$aix_level" ]; then
    printf '%s\n' "  AIX oslevel: $aix_level"
  fi
  printf '%s\n' "  TUXDIR: ${TUXDIR:-not set}"
  printf '%s\n' "  Tuxedo installs found: $install_count"
  printf '%s\n' "  Version: $version_line"
  printf '\n%s\n' "Answer 2 - Client mode and language"
  printf '%s\n' "  Client mode: $client_mode"
  printf '%s\n' "  WSNADDR: ${WSNADDR:-not set}"
  printf '%s\n' "  TUXCONFIG: ${TUXCONFIG:-not set}"
  printf '%s\n' "  TOBJADDR: ${TOBJADDR:-not set}"
  if [ -n "$APP_DIR" ]; then
    printf '%s\n' "  Application directory: $APP_DIR"
  else
    printf '%s\n' "  Application directory: not supplied. Pass the client application directory to classify the binary."
  fi
  printf '\n%s\n' "Answer 3 - Buffer types, conversations, and transactions"
  printf '%s\n' "  FLDTBLDIR32: ${FLDTBLDIR32:-not set}"
  printf '%s\n' "  FIELDTBLS32: ${FIELDTBLS32:-not set}"
  printf '%s\n' "  FML32 field tables: $field_count"
  printf '%s\n' "  VIEW32: $view_state"
  printf '%s\n' "  Tokens: $token_line"
  printf '\n%s\n' "Answer 4 - 64-bit libraries and field tables for replay"
  printf '%s\n' "  64-bit workstation libraries: $wsc64"
  printf '%s\n' "  32-bit workstation libraries: $wsc32"
  printf '%s\n' "  64-bit native libraries: $tux64"
  printf '%s\n' "  Field tables: $field_count"
  printf '%s\n' "  Replay readiness: $replay"
  printf '\n%s\n' "Evidence"
  cat "$BODY"
  printf '\n%s\n' "Next step"
  printf '%s\n' "  Copy this report back. Review it before sharing: it contains host names and file paths."
} > "$OUT"

cat "$OUT"
printf '\n%s\n' "Wrote $OUT"
