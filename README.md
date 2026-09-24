# agent-guardian — the agent firewall

One file. Stdlib only. Zero dependencies. It sits in front of every shell
command your AI agent wants to run and answers one question: **is this safe?**

- exit `0` — clean
- exit `1` — **WARN** (advisory, you can override)
- exit `2` — **DENY** (hard stop)

Every verdict comes with machine-readable receipts (`--json`), so safety
evals can consume the allow/deny stream directly.

## 60-second demo

```bash
curl -o guardian.py https://raw.githubusercontent.com/empire-mind/agent-guardian/main/guardian.py
python3 guardian.py --cmd 'rm -rf /'        # DENY, exit 2
python3 guardian.py --cmd 'rm -rf /tmp/x'   # WARN, exit 1
python3 guardian.py --cmd 'git status'      # clean, exit 0
```

Or run the tour:

```bash
python3 examples/hello-guardian.py
```

## What it checks

**DENY (hard stop)** — tiny set of catastrophic *simple* commands:
`rm -r[f]` targeting `/`, `~`, or `$HOME` (including when hidden behind
`&&` in a compound command), fork bombs.

**WARN (advisory)** — destructive families: recursive deletes, `DROP` /
`TRUNCATE`, `git push --force`, `git reset --hard`, `kubectl delete`,
`docker rm -f` / `system prune`, `chmod 777`, `curl | sh`, `dd` to raw
devices, `mkfs`, and a shell-obfuscation tripwire (`${IFS}` splitting,
base64-decode-piped-to-shell).

**Allowed, not warned** — a single `rm -r[f]` whose targets are *all*
throwaway build artifacts (`node_modules`, `dist`, `__pycache__`, …).

**Edit boundaries** (`/freeze`-style): `--path <file> --boundary <dir>`
returns DENY (exit 2) when an edit lands outside the declared directory.

```bash
echo 'git push --force' | python3 guardian.py          # stdin also works
python3 guardian.py --cmd 'rm -rf /' --json            # machine-readable
python3 guardian.py --path /etc/passwd --boundary ~/workspace
```

## Honest limits

- **Regex + crude tokenization, not a parser.** A determined adversary can
  craft commands this doesn't catch (`xargs rm`, exotic quoting). Guardian
  is a tripwire for *accidental* destruction by agents, not a sandbox
  against a malicious actor. See the open issues for the adversarial-corpus
  work that measures exactly this.
- **WARN means warn-and-continue** in our wiring. The one exception: a root
  delete hidden inside a compound command is always DENY (see
  `_high_rm_root_anywhere`).
- If you need filesystem isolation, you need a container — this is one file
  of Python.

## Attribution

Methodology adapted from [garrytan/gstack](https://github.com/garrytan/gstack)
(MIT © 2026 Garry Tan) — the `/careful`, `/guard`, and `/freeze` skills.
Reimplemented here in stdlib-only Python; see the header of `guardian.py`.

## Development

```bash
python3 -m pytest tests/    # 26 tests, offline, no dependencies beyond pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full funnel.

## Contributing

We keep a simple, keepable promise: **every issue and external PR gets a
first response within 7 calendar days.** Good first issues are scoped for
one evening — start there. Full details in
[CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see the org
[SECURITY.md](https://github.com/empire-mind/.github/blob/main/SECURITY.md) —
please don't open a public issue for those.

## License

MIT — see [LICENSE](LICENSE).
