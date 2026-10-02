# False-Positive Audit Table for MEDIUM Patterns (`docs/false-positives.md`)

This document provides a comprehensive false-positive audit across all 12 `MEDIUM` advisory detection patterns in `guardian.py`.

In line with our **Honest Limits** methodology, we document where static regex patterns trigger warnings on benign developer commands, analyzing whether each advisory warning (`WARN`, exit 1) represents **Justified Caution** (intentional human check on dangerous capabilities) or **Noise** (unintended collateral from broad string heuristics).

---

## Audit Summary Table

| Pattern Name | Benign Command Trigger | Verdict | Assessment | Rationale & Recommendation |
|---|---|---|---|---|
| `rm_recursive` | `rm -rf /tmp/my-test-tempdir` | `WARN` | Justified | Non-whitelisted recursive delete; appropriately alerts operator before filesystem destruction. |
| `rm_recursive` | `rm -r ./site-build-scratch` | `WARN` | Justified | Unrecognized build folder; operator should whitelist or verify path. |
| `rm_recursive` | `rm -R tests/artifacts` | `WARN` | Justified | Recursive file wipe. Safe in context, but warrants an advisory check. |
| `drop_table` | `sqlite3 test.db "DROP TABLE IF EXISTS temp_migration_staging;"` | `WARN` | Justified | Dropping ephemeral scratch tables is benign, but DDL drop in production databases is catastrophic. |
| `drop_table` | `psql -c "DROP TABLE scratch_import;"` | `WARN` | Justified | Advisory flag ensures the agent is connected to the right test database. |
| `drop_table` | `mysql -e "DROP TABLE staging_users;"` | `WARN` | Justified | Structural table deletion caution is warranted. |
| `truncate` | `truncate -s 0 /var/log/custom-test.log` | `WARN` | **Noise** | Unix coreutils `truncate` utility zeros file sizes; regex confuses it with SQL `TRUNCATE TABLE`. *Follow-up: require SQL context or table token.* |
| `truncate` | `truncate -s 10M test_sparse_file.bin` | `WARN` | **Noise** | Allocating sparse files via coreutils `truncate` is completely non-destructive. *Follow-up: disambiguate shell utility from SQL query.* |
| `truncate` | `sqlite3 app.db "TRUNCATE staging_cache;"` | `WARN` | Justified | SQL table truncate removes all table records. |
| `git_force_push` | `git push --force-with-lease origin feat/my-branch` | `WARN` | Justified | `--force-with-lease` is best practice for feature branches, but history rewriting still warrants visibility. |
| `git_force_push` | `git push origin +refs/heads/wip-experiment` | `WARN` | Justified | Plus syntax (`+`) force-pushes the refspec, which can overwrite remote work. |
| `git_force_push` | `git push -f my-fork fix/issue-123` | `WARN` | Justified | Pushing rebased branch to personal fork is standard; advisory check ensures correct remote fork. |
| `git_reset_hard` | `git reset --hard HEAD` | `WARN` | Justified | Discards uncommitted working tree changes permanently; advisory warning prevents unintentional data loss. |
| `git_reset_hard` | `git reset --hard @{u}` | `WARN` | Justified | Rewrites local branch state to match upstream tracking tip. |
| `git_reset_hard` | `git reset --hard v1.0.0` | `WARN` | Justified | Resets branch pointer back to previous release tag. |
| `git_discard_tree` | `git checkout .` | `WARN` | Justified | Wipes all unstaged local file changes in current directory. |
| `git_restore_tree` | `git restore .` | `WARN` | Justified | Modern Git equivalent of `checkout .`; discards working tree edits. |
| `git_discard_tree` | `git checkout . && git clean -fd` | `WARN` | Justified | Completely cleans and restores repository working copy. |
| `kubectl_delete` | `kubectl delete pod ephemeral-debug-runner` | `WARN` | Justified | Deleting ephemeral debug pod is standard, but kubectl cluster target requires validation. |
| `kubectl_delete` | `kubectl delete -f local-kind-cluster-test.yaml` | `WARN` | Justified | Tearing down local test resources; advisory warning confirms correct context. |
| `kubectl_delete` | `kubectl delete configmap test-config-temp` | `WARN` | Justified | Removing temporary configuration maps. |
| `docker_destructive`| `docker rm -f test_container` | `WARN` | Justified | Force-removing test containers in CI scripts is normal, but warns if run against production daemons. |
| `docker_destructive`| `docker system prune --volumes` | `WARN` | Justified | Reclaiming disk space on developer workstation; destructive if volumes contain persistent databases. |
| `docker_destructive`| `docker rm -f my_stopped_test` | `WARN` | Justified | Force killing containers warrants advisory confirmation. |
| `chmod_777` | `chmod 777 /tmp/shared_test_socket.sock` | `WARN` | Justified | Permissive permissions on IPC sockets is common in local dev, but unacceptable in shared/prod hosts. |
| `chmod_777` | `chmod -R 777 ./local_dev_uploads` | `WARN` | Justified | Resolves Docker container volume write permissions locally, but world-writable mode is insecure. |
| `chmod_777` | `chmod 777 /tmp/debug.log` | `WARN` | Justified | Allowing multi-user log writes; advisory warning prevents permission misconfigurations. |
| `curl_pipe_sh` | `curl -sSf https://sh.rustup.rs \| sh` | `WARN` | Justified | Official Rustup installer, but executing unpinned remote code without hash verification is inherently risky. |
| `curl_pipe_sh` | `curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh \| bash` | `WARN` | Justified | Official nvm installer script; warrants advisory review. |
| `curl_pipe_sh` | `curl -fsSL https://starship.rs/install.sh \| sh` | `WARN` | Justified | Shell prompt installer; advisory notice flags network pipe execution. |
| `dd_raw_device` | `dd if=/dev/urandom of=/dev/stdout bs=1k count=1` | `WARN` | **Noise** | `/dev/stdout` and `/dev/null` are pseudo-devices, not physical raw storage disks. *Follow-up: exclude `/dev/std*` and `/dev/null`.* |
| `dd_raw_device` | `dd if=/dev/zero of=/dev/null bs=1M count=100` | `WARN` | **Noise** | Throughput benchmark targeting `/dev/null`. *Follow-up: match physical block devices `/dev/sd*`, `/dev/nvme*`, `/dev/disk*`.* |
| `dd_raw_device` | `dd if=/dev/zero of=/dev/stdout bs=100` | `WARN` | **Noise** | Piping zero streams to standard output. |
| `mkfs` | `mkfs.ext4 -F /tmp/test_virtual_disk.img` | `WARN` | Justified | Formatting disk images in testing environments; formatting disks is inherently high-impact. |
| `mkfs` | `mkfs.vfat -C /tmp/test_usb.img 1440` | `WARN` | Justified | Creating virtual floppy disk images for tests. |
| `mkfs` | `mkfs.btrfs -f /dev/loop0` | `WARN` | Justified | Formatting loop devices in integration suites. |

---

## Actionable Tuning Recommendations (Future Work)

1. **`truncate` Command Disambiguation:**
   - Current: `r"(?i)\btruncate\b"` triggers on coreutils `truncate -s 0 file.log`.
   - Tuning: Require SQL context (`r"(?i)\btruncate\s+(table\s+)?[a-zA-Z0-9_.]+"`) or ignore when accompanied by `-s` / `--size` flags.
2. **`dd_raw_device` Exclusions:**
   - Current: `r"\bdd\b[^\n]*\bof=/dev/"` triggers on `of=/dev/null` and `of=/dev/stdout`.
   - Tuning: Narrow pattern to physical disks (`r"\bdd\b[^\n]*\bof=/dev/(sd[a-z]|nvme|disk|vd[a-z]|hd[a-z])"`).
