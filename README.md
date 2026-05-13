# copyfail-sh

> No race. No offsets. No prebuilt binary to blindly trust.

A bash implementation of CVE-2026-31431 (Copy Fail). The script compiles a minimal C helper inline at runtime. The bash layer handles architecture detection, payload decompression and target selection; the C layer does the actual kernel interaction (AF_ALG sockets, `splice`, `sendmsg`) that bash can't reach on its own.

See [copy.fail](https://copy.fail) for the full technical breakdown.

## How it works (tl;dr)

The bug is in `algif_aead`, the kernel's AF_ALG AEAD socket interface. A 2017 in-place optimization lets page-cache pages end up in the writable destination scatterlist of an `authencesn` decryption operation. Feed it the right input via `splice()` and you get a deterministic 4-byte write into the page cache of any readable file, including setuid binaries you don't own.

Overwrite `/usr/bin/su` with shellcode 4 bytes at a time, run it, get a root shell. No race window, no kernel-specific symbols, no retries.

## Usage

```bash
chmod +x copyfail.sh

# Check if the system is vulnerable before doing anything
./copyfail.sh -c

# Run the exploit (must be non-root)
./copyfail.sh

# Specify a different setuid target
./copyfail.sh -t /usr/bin/passwd

# List all setuid-root candidates on the system
./copyfail.sh -s
```

### Restoring su after getting a shell

The exploit overwrites the page cache in memory only, the file on disk is untouched. A reboot restores everything. If you want to clean up immediately:

```bash
# Inside your root shell
/usr/bin/su --version   # still works from disk if page cache is evicted
# Or just reboot
```

If you used `-t` with something other than `su`, same deal. Page cache only, disk is clean.

## Requirements

- Linux (kernel 4.11 to 7.0, see below)
- `gcc` to compile the inline C helper
- `python3` to decompress the shellcode payload (one-liner, no packages needed)
- Kernel modules: `algif_aead`, `authencesn`, `hmac`, `cbc`

If the algo isn't available:

```bash
sudo modprobe algif_aead authencesn hmac cbc
```

Some distros ship a block in `/etc/modprobe.d/` as a temporary workaround. Remove it if present:

```bash
sudo rm /etc/modprobe.d/disable-algif{_,-}aead.conf 2>/dev/null
```

## Affected kernels

```
floor:    torvalds/linux 72548b093ee3   August 2017, v4.14
                                        (AF_ALG iov_iter rework that introduced
                                         the file-page write primitive via splice
                                         into the AEAD scatterlist)

ceiling:  torvalds/linux a664bf3d603d   April 2026, mainline
                                        (reverts the 2017 in-place optimization;
                                         source and destination scatterlists are
                                         now separate, page-cache pages can no
                                         longer end up as writable crypto output)
```

Between those two commits: every major distro that didn't backport the fix. Ubuntu, RHEL, SUSE, Amazon Linux, Debian were all confirmed vulnerable at disclosure time. Distro backports started landing around 2026-04-29. To check a specific kernel, look for `a664bf3d603d` (or its distro backport) in the changelog.

## Supported architectures

| Arch | Status |
|---|---|
| x86_64 | ✓ |
| aarch64 | ✓ |
| i386 / i686 | ✓ |
| armv7l | ✓ |

## Mitigation

**Permanent:** update your kernel.

**Workaround** (blocks the AF_ALG socket; does not affect IPsec/XFRM which uses the kernel crypto API directly):

```bash
echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif-aead.conf
sudo rmmod algif_aead 2>/dev/null
```

**Containers:** add a seccomp profile that blocks `AF_ALG` socket creation, and set `allowPrivilegeEscalation: false` in your pod security context. This enables `no_new_privs` which stops the kernel from honouring setuid bits on `execve()`.

## Compared to the other implementations

| | Python | Go | **Bash** |
|---|---|---|---|
| Dependency | python3 | none (static binary) | gcc + python3 |
| Prebuilt binary | no | yes | no |
| Single file | yes | no | yes |
| Compilation step | no | no | yes (inline, auto) |

The bash version won't win on dependencies, but it's a single script you can read end-to-end before running. The C helper is generated and compiled at runtime from a heredoc, no binary blob to audit separately.

## References

- [copy.fail](https://copy.fail) - official site and write-up
- [Xint.io blog](https://xint.io/blog/copy-fail-linux-distributions) - technical deep-dive
- [Kernel fix - a664bf3d603d](https://github.com/torvalds/linux/commit/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [CVE-2026-31431 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)
- [oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [badsectorlabs/copyfail-go](https://github.com/badsectorlabs/copyfail-go) - Go implementation (shellcode payloads sourced from here)
- [xeloxa/copyfail-exploit](https://github.com/xeloxa/copyfail-exploit) - Python implementation

## Credits

- **Taeyang Lee & Theori / Xint Code** - vulnerability discovery and original PoC

## Disclaimer

For authorised security testing and research only. Don't run this on systems you don't own or have explicit written permission to test.
