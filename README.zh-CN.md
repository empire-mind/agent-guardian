# agent-guardian — 智能体防火墙

[English](README.md) | 简体中文

单一文件。仅依赖标准库。零第三方依赖。它守护在你的 AI 智能体想要运行的每一个 Shell 命令之前，回答一个核心问题：**这个操作安全吗？**

- 退出码 `0` — 安全（clean）
- 退出码 `1` — **警告（WARN）**（建议性质，可覆盖执行）
- 退出码 `2` — **拒绝（DENY）**（硬性阻断）

每个裁决都附带机器可读的凭据（`--json`），以便安全评测流程直接读取允许/拒绝流。

## 60 秒快速演示

```bash
curl -o guardian.py https://raw.githubusercontent.com/empire-mind/agent-guardian/main/guardian.py
python3 guardian.py --cmd 'rm -rf /'        # DENY, exit 2
python3 guardian.py --cmd 'rm -rf /tmp/x'   # WARN, exit 1
python3 guardian.py --cmd 'git status'      # clean, exit 0
```

或者运行完整演示：

```bash
python3 examples/hello-guardian.py
```

## 检测范围

**DENY（硬性阻断）** — 针对极少数灾难性的*简单*命令：
目标为 `/`、`~` 或 `$HOME` 的 `rm -r[f]`（包括在复合命令中隐藏在 `&&` 之后的场景）、Fork 炸弹。

**WARN（建议性警告）** — 破坏性命令族：递归删除、`DROP` / `TRUNCATE`、`git push --force`、`git reset --hard`、`kubectl delete`、`docker rm -f` / `system prune`、`chmod 777`、`curl | sh`、写入裸设备的 `dd`、`mkfs` 以及 Shell 混淆陷阱（`${IFS}` 切分、base64 解码管道传递给 Shell）。

**允许执行，不予警告** — 单条 `rm -r[f]` 且其目标*全部*为一次性构建产物（`node_modules`、`dist`、`__pycache__` 等）。

**编辑边界**（`/freeze` 风格）：`--path <file> --boundary <dir>`
当编辑超出声明的目录范围时返回 DENY（退出码 2）。

```bash
echo 'git push --force' | python3 guardian.py          # 支持 stdin
python3 guardian.py --cmd 'rm -rf /' --json            # 机器可读输出
python3 guardian.py --path /etc/passwd --boundary ~/workspace
```

## 坦白局限性（Honest limits）

- **基于正则表达式与基础分词，而非完整的语法解析器。** 蓄意的攻击者可以通过特殊构造绕过检查（如 `xargs rm`、特殊引号等）。Guardian 是防范智能体*无意间*造成破坏的绊线，而非防范恶意攻击者的沙箱。请参阅对抗语料库相关 Issue，其中精确评估了这些场景。
- 在我们的接入逻辑中，**WARN 意味着警告并继续执行**。唯一的例外是：隐藏在复合命令中的根目录删除始终会被 DENY（参见 `_high_rm_root_anywhere`）。
- 如果你需要文件系统隔离，请使用容器——本工具仅为一个独立的 Python 文件。

## 致谢

方法论改编自 [garrytan/gstack](https://github.com/garrytan/gstack) (MIT © 2026 Garry Tan) 中的 `/careful`、`/guard` 和 `/freeze` 技能。
以纯标准库 Python 重新实现；详见 `guardian.py` 头部说明。

## 开发

```bash
python3 -m pytest tests/    # 26 tests, offline, no dependencies beyond pytest
```

完整参与流程请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 贡献指南

我们信守一个简单、可兑现的承诺：**每个 Issue 和外部 PR 都会在 7 个自然日内获得首次回复。** Good first issue 任务设计为一个晚上即可完成——建议从那里开始。完整细节见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题报告：请阅读组织的 [SECURITY.md](https://github.com/empire-mind/.github/blob/main/SECURITY.md) —— 请不要为此创建公开 Issue。

## 许可证

MIT — 详见 [LICENSE](LICENSE)。
