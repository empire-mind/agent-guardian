#!/usr/bin/env python3
"""guardian.py — destructive-command scanner for code-factory bash runs.

Adapted (methodology + pattern families) from Garry Tan's gstack
(https://github.com/garrytan/gstack, MIT license) — the /careful, /guard and
/freeze skills. Reimplemented here in stdlib-only Python for the org's
code-factory execution plane. Copyright of the original: (c) 2026 Garry Tan.

Usage:
    guardian.py --cmd 'rm -rf /tmp/build'     # scan one shell command
    echo 'git push --force' | guardian.py      # or read from stdin
    guardian.py --path some/file.py --boundary ~/workspace   # /freeze-style
                                                             # edit-boundary check

Exit codes: 0 = clean, 1 = WARN (advisory, overridable), 2 = DENY (hard stop).

Tiers mirror gstack's /careful: HIGH = tiny set of catastrophic SIMPLE
commands -> DENY; MEDIUM = destructive families -> WARN (always overridable).
/freeze's idea: edits outside a declared boundary are DENY.
"""

import argparse
import os
import re
import sys

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# Patterns (MEDIUM tier — advisory warns). Each: (name, regex, explanation)
# ---------------------------------------------------------------------------
_MEDIUM = [
    ("rm_recursive",
     r"\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)\b",
     "Destructive: recursive delete (rm -r). Permanently removes files."),
    ("drop_table",
     r"(?i)\bdrop\s+(table|database)\b",
     "Destructive: SQL DROP detected. Permanently deletes database objects."),
    ("truncate",
     r"(?i)\btruncate\b",
     "Destructive: SQL TRUNCATE detected. Deletes all rows from a table."),
    ("git_force_push",
     r"\bgit\s+push\b.*(-f\b|--force\b|(?<= )\+[^\s])",
     "Destructive: git force-push rewrites remote history. Others may lose work."),
    ("git_reset_hard",
     r"\bgit\s+reset\s+--hard\b",
     "Destructive: git reset --hard discards all uncommitted changes."),
    ("git_discard_tree",
     r"\bgit\s+(checkout|restore)\s+\.(?=\s|$)",
     "Destructive: discards all uncommitted changes in the working tree."),
    ("kubectl_delete",
     r"\bkubectl\s+delete\b",
     "Destructive: kubectl delete removes Kubernetes resources; may hit prod."),
    ("docker_destructive",
     r"\bdocker\s+(rm\s+-f|system\s+prune)\b",
     "Destructive: docker force-remove or prune; may delete running containers."),
    ("chmod_777",
     r"\bchmod\s+(-R\s+)?777\b",
     "Risky: chmod 777 makes files world-writable."),
    ("curl_pipe_sh",
     r"\bcurl\b[^|]*\|\s*(sh|bash)\b",
     "Risky: piping a download straight into a shell executes remote code."),
    ("dd_raw_device",
     r"\bdd\b[^\n]*\bof=/dev/",
     "Destructive: dd writing to a raw device can destroy a disk/partition."),
    ("mkfs",
     r"\bmkfs(\.\w+)?\b",
     "Destructive: mkfs formats a filesystem, destroying its contents."),
]

# Obfuscation tripwire (gstack /careful idea): ${IFS}-splitting or
# base64-decode-piped-to-shell means the string hides what it executes.
_OBFUSCATION = re.compile(
    r"\$\{IFS\}|\$IFS|\$\(\s*echo[^)]*base64|base64\s+(-d|--decode)[^|]*\|\s*(sh|bash)"
)

# ---------------------------------------------------------------------------
# HIGH tier — hard DENY, simple commands only.
# ---------------------------------------------------------------------------
_ROOT_TOKENS = {"/", "~", "~/", "$HOME", "$HOME/", "${HOME}", "${HOME}/", "/*", "//"}


def _tokens(cmd):
    """Crude tokenization (word-splitting), one quote layer stripped."""
    toks = []
    for t in cmd.split():
        if len(t) >= 2 and ((t[0] == '"' and t[-1] == '"') or (t[0] == "'" and t[-1] == "'")):
            t = t[1:-1]
        toks.append(t)
    return toks


def _high_rm_root(cmd):
    """rm -r[f] where EVERY non-option token is a root-class target."""
    if not re.match(r"^\s*(sudo\s+)?rm\s", cmd):
        return False
    if not re.search(r"(^|\s)(-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)(\s|$)", cmd):
        return False
    # Compound commands fall through to MEDIUM (conservative = warn, never guess).
    if re.search(r"[;&|\n]", cmd):
        return False
    root = safe = False
    for tok in _tokens(cmd):
        if tok in ("sudo", "rm", "--") or tok.startswith("-") or re.match(r"^\d?>", tok) or tok == "&":
            continue
        if tok in _ROOT_TOKENS:
            root = True
        else:
            safe = True
    return root and not safe


def _high_rm_root_anywhere(cmd):
    """Split compound commands into simple segments; DENY if ANY segment is a
    root-targeted recursive delete. Unlike gstack's interactive ask-tier, our
    WARN means 'warn and continue', so a root delete hidden behind && must not
    degrade to a warning — the segment analysis stays purely syntactic."""
    segments = re.split(r"&&|\|\||[;&|\n]", cmd)
    return any(_high_rm_root(seg) for seg in segments)


def _high_forkbomb(cmd):
    return bool(re.search(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;", cmd))


# Safe exception (gstack /careful idea): a single-line rm -r<f> whose targets are
# ALL throwaway build artifacts is allowed, not warned.
_SAFE_ARTIFACTS = {"node_modules", ".next", "dist", "__pycache__", ".cache",
                   "build", ".turbo", "coverage"}


def _is_safe_artifact_rm(cmd):
    if re.search(r"[;&|\n]", cmd):
        return False
    toks = _tokens(cmd)
    if not toks or toks[0] not in ("rm", "sudo"):
        return False
    i = 1 if toks[0] == "rm" else 2
    if toks[0] == "sudo" and (len(toks) < 2 or toks[1] != "rm"):
        return False
    if not re.fullmatch(r"-[a-zA-Z]*[rR][a-zA-Z]*|--recursive", toks[i]):
        return False
    targets = toks[i + 1:]
    if not targets:
        return False
    return all(t.rstrip("/").split("/")[-1] in _SAFE_ARTIFACTS for t in targets)


def scan_command(cmd):
    """Return (tier, findings). tier in {'clean','warn','deny'}."""
    findings = []
    if _high_rm_root(cmd) or _high_rm_root_anywhere(cmd):
        findings.append(("high_rm_root",
                         "Recursive delete of / or the whole home directory is blocked."))
    if _high_forkbomb(cmd):
        findings.append(("high_forkbomb", "Fork bomb detected — blocked."))
    if _OBFUSCATION.search(cmd):
        findings.append(("obfuscation",
                         "Shell obfuscation detected (${IFS} splitting or base64-to-shell). "
                         "Read the command carefully before running."))
    for name, pattern, why in _MEDIUM:
        if name == "rm_recursive" and _is_safe_artifact_rm(cmd):
            continue  # whitelisted: nuking build artifacts only
        if re.search(pattern, cmd):
            findings.append((name, why))
    tier = "clean"
    if findings:
        tier = "deny" if any(n.startswith("high_") for n, _ in findings) else "warn"
    return tier, findings


def check_path_within_boundary(path, boundary):
    """Freeze-style boundary check. Returns True if path is inside boundary."""
    b = os.path.realpath(os.path.expanduser(boundary))
    p = os.path.realpath(os.path.expanduser(path))
    return p == b or p.startswith(b + os.sep)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="guardian",
                                 description="destructive-command / edit-boundary scanner")
    ap.add_argument("--cmd", default=None, help="shell command string to scan")
    ap.add_argument("--path", default=None, help="file path to check against --boundary")
    ap.add_argument("--boundary", default=None, help="allowed directory for --path")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--version", action="store_true", help="print the version and exit")
    args = ap.parse_args(argv)

    if args.version:
        print(__version__)
        return 0

    if args.path is not None:
        if not args.boundary:
            print("guardian: --path requires --boundary", file=sys.stderr)
            return 2
        inside = check_path_within_boundary(args.path, args.boundary)
        if args.json:
            import json
            print(json.dumps({"tier": "clean" if inside else "deny",
                              "path": args.path, "boundary": args.boundary}))
        else:
            print("clean: within boundary" if inside
                  else f"DENY: {args.path} is outside boundary {args.boundary}")
        return 0 if inside else 2

    cmd = args.cmd if args.cmd is not None else sys.stdin.read()
    if not cmd.strip():
        print("guardian: no command supplied", file=sys.stderr)
        return 2
    tier, findings = scan_command(cmd)
    if args.json:
        import json
        print(json.dumps({"tier": tier,
                          "findings": [{"pattern": n, "why": w} for n, w in findings]}))
    else:
        if tier == "clean":
            print("guardian: clean")
        else:
            label = "DENY" if tier == "deny" else "WARN"
            for name, why in findings:
                print(f"guardian [{label}] {name}: {why}")
    return {"clean": 0, "warn": 1, "deny": 2}[tier]


if __name__ == "__main__":
    sys.exit(main())
