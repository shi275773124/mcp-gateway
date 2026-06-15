# MCP Gateway

> ChatGPT 做大脑，你的本地机器做双手。白名单安全。150 行。

把 ChatGPT 网页端的 GPT-5.5 Pro 连接到你的本地文件系统和终端 —— 通过 MCP（Model Context Protocol），走你自己的代码，不依赖任何第三方。

## 为什么不用 localant

localant 是个 6 天新包，1 star 0 fork，单人维护。默认安全模式是黑名单（deny-list），权限模型是"除了我列出来的都允许"。

我们写了自己的。白名单（allow-list）。你说哪些目录能碰、哪些命令能跑，其余全部拒绝。危险命令硬编码拒绝，改都改不了。

## 架构

```
ChatGPT (浏览器) → CF Tunnel → MCP Gateway (本地 Python) → 你的文件/终端
                      ↑
              你控制的域名/隧道
```

## 快速开始

```bash
git clone https://github.com/shi275773124/mcp-gateway.git
cd mcp-gateway
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 1. 配置

```bash
cp config.example.json config.json
# 编辑 config.json 设置你的 allowed_dirs, allow_write, allow_shell
```

### 2. 启动

```bash
python3 server.py
```

输出：
```
Starting MCP Gateway on 127.0.0.1:8000
MCP endpoint: http://127.0.0.1:8000/mcp
```

### 3. 内网穿透

```bash
# 快速隧道（测试用，URL 每次变）
cloudflared tunnel --url http://127.0.0.1:8000

# 或用自己的 CF Tunnel（生产用）
cloudflared tunnel create mcp-gateway
cloudflared tunnel route dns mcp-gateway mcp.yourdomain.com
cloudflared tunnel run mcp-gateway --url http://127.0.0.1:8000
```

### 4. 接入 ChatGPT

1. ChatGPT → 设置 → 应用和连接器
2. 开发者模式 → 开启
3. 新建 Connector → 类型选 MCP
4. 填入：`https://your-tunnel-url/mcp`
5. 认证选"无"(token 走 query string) 或用 Bearer Token

## 安全模型

| 模式 | 文件系统 | Shell | 说明 |
|------|---------|-------|------|
| 白名单 | 只允许 `allowed_dirs` | 只允许 `allowed_commands` | 默认 |
| 硬拒绝 | `~/.ssh` `~/.aws` `/etc` 等 | `sudo` `rm -rf` `dd` 等 | 永远不可绕过 |

审计日志：每次操作记录到 `~/.mcp-gateway-audit.log`。

## 内置工具

| 工具 | 功能 |
|------|------|
| `read_file` | 读取文件（带行号） |
| `write_file` | 写入文件（需 `allow_write: true`） |
| `list_dir` | 列出目录 |
| `run_command` | 执行命令（需 `allow_shell: true`） |
| `git_status` | Git 状态 |
| `git_diff` | Git 差异 |
| `git_log` | Git 日志 |
| `health_check` | 网关健康检查 |

## License

MIT
