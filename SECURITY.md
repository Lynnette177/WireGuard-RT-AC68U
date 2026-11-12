# Configuration and publication safety

- Keep real WireGuard configuration in `conf.txt` or another ignored `.conf` file. Commit only `conf.example.txt` with placeholders.
- Never commit private keys, preshared keys, SSH identities, environment files, logs, router backups, or deployment archives. These are excluded by `.gitignore`; review staged files before every push.
- The addresses in documentation and tests are examples. Set `-RouterAddress` and the configuration for your own network. Router scripts obtain the actual LAN address from NVRAM.
- Status output omits private and preshared keys. Raw WireGuard UAPI responses can contain keys; do not post them in issues.
- Distributed executables are built with `-trimpath -buildvcs=false` and checked against `dist/SHA256SUMS`. These flags avoid embedding local source paths and private repository metadata.
- This public repository starts from a sanitized source snapshot. Private repository history, personal commit email, local toolchains and real configuration are not part of that snapshot.
- The optional campus addon keeps its real portal address and CA in ignored local files. Web credentials are encrypted in the browser for submission and stored as plaintext only in a root-only router directory; a router root administrator can read them.

If credentials are accidentally published, remove them from the public history and rotate the affected keys. Adding an ignore rule after committing a secret does not remove it from Git history.
