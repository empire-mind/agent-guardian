# Adversarial Bypass Notes (`docs/adversarial-notes.md`)

This document records 10 concrete command shapes that currently evade `guardian.py`'s regex and basic tokenization engine. In keeping with our design principle of **Honest Limits**, we explicitly document where syntactic pattern matching falls short and how next-generation parsers or sandbox architectures should address them.

---

### 1. File Find with Action Execution (`find / -delete`)
- **Command:** `find / -delete` or `find / -exec rm -rf {} +`
- **Evaded Check:** `_high_rm_root` (`r"^\s*(sudo\s+)?rm\s"`) and `_MEDIUM` (`rm_recursive`).
- **Why It Evades:** The command starts with binary `find`, not `rm`. The destructive flag (`-delete` or `-exec rm`) is evaluated by `find`, bypassing all `rm` prefixes.
- **Suggested Detection:** Parse flags for utility binaries known to execute actions (`find`, `fd`, `locate`), flagging `-delete` or subcommands containing destructive tokens.

---

### 2. Piped Command Execution (`xargs rm -rf /`)
- **Command:** `echo "/" | xargs rm -rf`
- **Evaded Check:** `_high_rm_root` (`r"^\s*(sudo\s+)?rm\s"`).
- **Why It Evades:** `_high_rm_root` expects `rm` as the head command token. Here `echo` is the head token and `rm` is an argument to `xargs`.
- **Suggested Detection:** Unwrap wrapper commands (`xargs`, `parallel`, `env`, `nohup`, `nice`) to inspect their invoked target binary and argument list.

---

### 3. Scripting Language Inline Tree Deletion (`python3 -c "import shutil; shutil.rmtree('/')"`)
- **Command:** `python3 -c "import shutil; shutil.rmtree('/')"`
- **Evaded Check:** All shell-level regex checks in `_MEDIUM` and `_ROOT_TOKENS`.
- **Why It Evades:** Destructive logic is encapsulated inside a string literal passed to an external runtime interpreter (`python3`), completely opaque to shell command regex.
- **Suggested Detection:** Static AST analysis for inline execution scripts (`python -c`, `node -e`, `ruby -e`) or containment via filesystem isolation/jail.

---

### 4. Multicall Binary Invocation (`busybox rm -rf /`)
- **Command:** `busybox rm -rf /`
- **Evaded Check:** `_high_rm_root` (`r"^\s*(sudo\s+)?rm\s"`).
- **Why It Evades:** The leading token is `busybox`, so the regex anchored at `^\s*(sudo\s+)?rm\s` fails to match the primary command.
- **Suggested Detection:** Normalize known multicall wrappers (`busybox`, `toybox`, `chroot`) by shifting the command index to the underlying utility.

---

### 5. String Evaluation and Shell Expansion (`eval "rm -rf /"`)
- **Command:** `eval "rm -rf /"`
- **Evaded Check:** `_high_rm_root` (`r"^\s*(sudo\s+)?rm\s"`).
- **Why It Evades:** The initial token is `eval`. The actual destructive command is nested inside a quoted string that the shell unpacks at runtime.
- **Suggested Detection:** Detect `eval` or `sh -c` invocations and recursively analyze the inner expression string through `scan_command`.

---

### 6. Piped Base64 Decoding without Shell Execution (`echo "Lw==" | base64 -d | xargs rm -rf`)
- **Command:** `echo "Lw==" | base64 -d | xargs rm -rf`
- **Evaded Check:** `_OBFUSCATION` (`r"base64\s+(-d|--decode)[^|]*\|\s*(sh|bash)"`).
- **Why It Evades:** `_OBFUSCATION` only flags base64 piped to `sh` or `bash`. Pipelining to `xargs rm -rf` avoids matching the shell sink.
- **Suggested Detection:** Broaden pipe tracking to detect binary decoding outputs routed directly into filesystem mutation utilities.

---

### 7. Path Traversal & Normalization Tricks (`rm -rf /tmp/../`)
- **Command:** `rm -rf /tmp/../` or `rm -rf /var/log/../../`
- **Evaded Check:** `_ROOT_TOKENS` (`{"/", "~", "~/", "$HOME", "$HOME/", "${HOME}", "${HOME}/", "/*", "//"}`).
- **Why It Evades:** Tokenizer matches the literal token `"/tmp/../"`, which is not in `_ROOT_TOKENS`. However, canonical path resolution normalizes it to `/`.
- **Suggested Detection:** Run `os.path.realpath` / path canonicalization on non-flag arguments before root token membership testing.

---

### 8. Environment Command Dispatcher (`env rm -rf /`)
- **Command:** `env rm -rf /` or `/usr/bin/env rm -rf /`
- **Evaded Check:** `_high_rm_root` (`r"^\s*(sudo\s+)?rm\s"`).
- **Why It Evades:** Prepending `env` masks the primary utility from the anchored regular expression.
- **Suggested Detection:** Strip standard utility wrappers (`env`, `time`, `stdbuf`, `timeout`) during token stream preprocessing.

---

### 9. Subshell Invocation (`sh -c 'rm -rf /'`)
- **Command:** `sh -c 'rm -rf /'` or `bash -c 'rm -rf ~'`
- **Evaded Check:** `_high_rm_root` (`r"^\s*(sudo\s+)?rm\s"`).
- **Why It Evades:** Command token is `sh` or `bash`, not `rm`. The destructive argument is passed via the `-c` flag.
- **Suggested Detection:** When shell interpreters are invoked with `-c`, parse and scan the command string argument.

---

### 10. Perl/Ruby One-Liner File Unlinking (`perl -e 'unlink glob("/tmp/*")'`)
- **Command:** `perl -e 'unlink glob("/tmp/*")'`
- **Evaded Check:** All `rm`-based heuristics.
- **Why It Evades:** Native system calls (`unlink`, `rmdir`) executed within high-level scripting one-liners circumvent shell utility scanning entirely.
- **Suggested Detection:** Apply interpreter-specific security profiles, or require high-privilege execution gates when running ad-hoc scripts.
