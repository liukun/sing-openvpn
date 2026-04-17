# sing-openvpn

`sing-openvpn` 是一个基于 Go 语言实现的轻量级、高性能、纯用户态 OpenVPN 客户端库。它被设计为可以直接集成到各种代理软件（如 `sing-box`、`clash`）中，无需依赖操作系统的 TUN/TAP 驱动或 root 权限。

本项目通过集成 [gVisor](https://github.com/google/gvisor) 网络栈（由 `sing-wireguard` 提供），实现了完全在用户空间处理 IP 数据包，并对外提供了标准的代理接口 (`DialContext` 和 `ListenPacket`)。

## ✨ 核心特性

- **纯用户态实现**：内置 gVisor TUN 栈，无需操作系统 TUN 接口及管理员权限。
- **协议支持**：支持 OpenVPN UDP 和 TCP 协议连接，支持 `.ovpn` 配置文件解析。
- **TLS 控制通道**：
  - 完整的 TLS 握手及密钥交换 (`key_method_2`)。
  - 支持 `tls-auth`（HMAC 认证）和 `tls-crypt` (V1)（加密+认证）两种控制通道保护模式。
  - 支持动态配置协商 (`PUSH_REQUEST` / `PUSH_REPLY`)。
  - **高可靠控制流**：针对 UDP 丢包实现了带 ACK 确认机制的超时重传队列，确保恶劣网络下握手成功率。
- **数据通道加密**：
  - **AES-GCM** (如 `AES-128-GCM`, `AES-256-GCM`)
  - **AES-CBC** 结合 HMAC-SHA1 认证 (如 `AES-256-CBC`)
- **标准代理接口**：提供类似 `net.Dialer` 的接口，无缝桥接代理请求到 OpenVPN 隧道中。

## ⚡️ 极致性能与可靠性 (Optimizations)

经过深度的底层重构，本项目在数据面吞吐量和网络稳定性上达到了生产级标准：

- **Zero-Allocation 数据面**：
  - 全局复用 `sync.Pool` 管理网络读写 Buffer 和 `Packet` 解析对象。
  - **原地加解密 (In-place Cryptography)**：重写了 AES-GCM 和 AES-CBC 的底层调用，利用精确的预分配和切片操作，消除了每次收发数据包时产生的大量堆内存分配 (Heap Allocations)，极大地降低了 GC 压力。
  - **TCP 零拷贝发送**：TCP 模式下将 2 字节长度头与 Payload 预分配在同一内存块，避免 `append` 扩容或多次系统调用。
- **TUN 批量读写 (Batching)**：
  - 虚拟网卡读取升级为 Batch 模式（单次最多 32 个包），大幅减少跨态 Syscall 频率，成倍提升千兆网络下的吞吐上限。
- **滑动窗口防重放攻击 (Replay Protection)**：
  - 实现了基于 `uint64` 位掩码 (Bitmask) 的无锁防重放滑动窗口 (`ReplayWindow`)。
  - 在进行昂贵的 AES 解密前，**Fast-path** 优先校验 Packet ID，精准拦截恶意重放攻击与过期乱序包。
- **OpenVPN 标准 Keepalive**：
  - 内置 `pingLoop` 协程，按服务端推送的 `ping-restart N` 取 `N/2` 作为发送间隔，持续发送 `Ping Magic` 维持 NAT 会话（若服务端未推送则默认 10 秒）。
  - 基于无锁原子操作 (`atomic`) 记录最后活跃时间，超过 `ping-restart` 秒未收到服务端数据则主动断开连接，彻底解决弱网下的“假死/断流”问题。

## 📦 安装

```bash
go get github.com/airofm/sing-openvpn
```

> **注意**：本项目要求 Go 1.26.1 或更高版本。

## 🚀 快速开始

以下是一个基本的使用示例，展示了如何直接通过 `.ovpn` 配置文件及凭据来初始化 OpenVPN 客户端，并发起代理请求。

```go
package main

import (
	"context"
	"log"
	"os"

	openvpn "github.com/airofm/sing-openvpn"
)

func main() {
	// 1. 读取 .ovpn 配置文件内容并初始化客户端
	// 也可以传入空字符串作为账号密码，如果服务器不需要密码认证
	// 最后一个参数 dialer 可用于指定底层网络连接方式（在集成到 sing-box/mihomo 等环境时可传入其 Dialer，直接使用直连可传 nil）
	ovpnContent, err := os.ReadFile("config.ovpn")
	if err != nil {
		log.Fatalf("Read config error: %v", err)
	}
	client, err := openvpn.NewClient(ovpnContent, "your_username", "your_password", nil)
	if err != nil {
		log.Fatalf("Init error: %v", err)
	}
	defer client.Close()

	// 2. 拨号连接到 OpenVPN 服务器并完成握手、建立用户态 TUN
	ctx := context.Background()
	if err := client.Dial(ctx); err != nil {
		log.Fatalf("Failed to connect OpenVPN: %v", err)
	}
	log.Println("OpenVPN connected successfully!")

	// 3. 通过 OpenVPN 隧道发起代理请求
	conn, err := client.DialContext(ctx, "tcp", "8.8.8.8:53")
	if err != nil {
		log.Fatalf("Failed to dial via VPN: %v", err)
	}
	defer conn.Close()

	// 现在你可以使用 conn 进行数据传输了...
}
```

## 🔌 SOCKS5 代理服务

项目内置了一个开箱即用的 SOCKS5 代理服务，可将本地 SOCKS5 流量透明转发至 OpenVPN 隧道，支持自动重连。

### 编译

需要 `with_gvisor` build tag 以启用 gVisor 用户态网络栈：

```bash
go build -tags with_gvisor -o socks5 ./cmd/socks5/
```

或无需编译直接运行：

```bash
go run -tags with_gvisor ./cmd/socks5/ config.toml
```

### 配置文件

创建 TOML 配置文件（参考 `cmd/socks5/config.example.toml`）：

```toml
[socks5]
listen = "127.0.0.1:6080"
# log_level: error, warn, info, debug, trace (default: debug)
# log_level = "info"
# auto_reconnect: auto reconnect on VPN disconnect (default: true)
# auto_reconnect = false

[openvpn]
ovpn_file = "/path/to/client.ovpn"
username = "myuser"

# 二选一：明文密码 或 脚本动态获取
password = "mypassword"
# password_script = "/path/to/get-password.sh"
```

| 字段 | 说明 |
|------|------|
| `socks5.listen` | SOCKS5 监听地址，默认 `127.0.0.1:6080` |
| `socks5.log_level` | 日志级别：`error` / `warn` / `info` / `debug` / `trace`，默认 `debug` |
| `socks5.auto_reconnect` | VPN 断线后是否自动重连，默认 `true` |
| `openvpn.ovpn_file` | `.ovpn` 配置文件路径 |
| `openvpn.username` | 用户名 |
| `openvpn.password` | 明文密码 |
| `openvpn.password_script` | 密码脚本路径（优先级高于 `password`），脚本输出的第一行作为密码 |

### 运行

```bash
./socks5 config.toml
```

启动后即可将浏览器或其他应用的代理设置指向 `socks5://127.0.0.1:6080`。

### 已知行为

- 日志中可能出现 `[ERR] socks: Failed to get version byte: EOF`，这是 go-socks5 库在客户端未发送数据就断开时打印的（如浏览器预连接、健康检查等），属于正常现象，可忽略。

## 🏗 架构说明

- **`config.go` / `parser.go`**: 外部配置模型及高度鲁棒的 `.ovpn` 配置文件解析器。
- **`client.go`**: 客户端核心逻辑，负责连接管理、`Dial` 核心逻辑、Ping-Restart 保活以及 `ListenPacket`/`DialContext` 接口。
- **`control.go`**: 可靠的控制通道，实现了基于 Packet ID 的 ACK 确认和带超时的滑动重传队列。
- **`handshake.go`**: 握手流程，处理 TLS 握手、`key_method_2` 密钥交换及 `PUSH_REPLY` 配置协商。
- **`transport.go`**: 传输层核心：无锁高吞吐的 UDP/TCP 读写循环事件总线。
- **`tun.go`**: 虚拟网卡层：批量 `tunReadLoop` (负责 gVisor 虚拟路由与数据并发加解密并写入网络)。
- **`internal/`**: 私有内部实现模块，包含：
  - **`crypto/`**: 数据通道的 `AES-CBC` / `AES-GCM` 零拷贝加解密、`tls-crypt` 包装、防重放滑动窗口 (`ReplayWindow`)，以及 PRF 密钥派生算法。
  - **`packet/`**: OpenVPN 协议数据包的高性能对象池化 (`sync.Pool`) 编码与解码。

## 📄 依赖说明

- [github.com/metacubex/sing](https://github.com/metacubex/sing)
- [github.com/metacubex/sing-wireguard](https://github.com/metacubex/sing-wireguard) (用于提供 gVisor 用户态 TUN 栈)
- [github.com/metacubex/tls](https://github.com/metacubex/tls)

## 📜 许可证

本项目遵循开源协议，详情请查看源码或许可证文件。