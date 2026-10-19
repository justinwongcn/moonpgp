# moonpgp

使用 MoonBit 编写的 OpenPGP 库，支持消息加解密、签名、密钥管理与 PGP/MIME 邮件工作流。

**模块：** `justinwongcn/moonpgp` · [包文档](https://mooncakes.io/docs/justinwongcn/moonpgp)

[English documentation](./README.mbt.md)

## 安装

需要 MoonBit 工具链。依赖由 `moon` 自动解析。

```bash
moon add justinwongcn/moonpgp
```

高层 API 可从根包导入；需要 PGP/MIME 或邮件组装时，分别导入 `mime` 和 `mail`：

```text
import {
  "justinwongcn/moonpgp",
  "justinwongcn/moonpgp/mime",
  "justinwongcn/moonpgp/mail",
}
```

根包将 `@api` 函数及其选项类型以 `@moonpgp.*` 导出。`mime` 和 `mail` 包分别提供 PGP/MIME 解析与 RFC 5322 邮件组装。

可克隆仓库运行命令行示例：

```bash
git clone https://github.com/justinwongcn/moonpgp
cd moonpgp
moon run cmd/main -- help
```

## 功能

- **密钥：** 导入、导出、生成、加锁和解锁 OpenPGP 密钥。支持 RSA、Ed25519（EdDSA legacy）及 Curve25519/X25519 工作流；默认生成 v4 密钥，相关 API 也支持 v6。提供能力、过期和吊销状态检查。
- **消息：** 公钥与口令加密；分离、内联和明文签名；会话密钥操作；可选 ZIP/ZLIB 压缩。生成消息使用 AES；CAST5 和 3DES 仅用于解密。
- **现代格式：** 支持 v6 密钥与消息，包括 v6 PKESK/SKESK 及采用 OCB、EAX 或 GCM AEAD 的 v2 SEIPD。标准 v4 收件人和口令工作流默认使用 v1 SEIPD。
- **口令保护：** 支持迭代加盐 S2K、Argon2 S2K，以及相应支持的 AEAD 私钥保护格式。
- **邮件：** `mime` 解析并验证 PGP/MIME 邮件；`mail` 组装 RFC 5322 邮件，包括 PGP/MIME 签名与加密。SMTP/IMAP 客户端位于 `example/`，属于示例而非库 API，且仅支持 native。

## 互操作与检查

测试套件包含与 GnuPG、OpenSSL 和 go-crypto 的部分互操作流程，以及 RFC 测试向量。GnuPG 互操作检查见 [`scripts/interop_check.sh`](./scripts/interop_check.sh)。

本地检查命令：

```bash
moon check --target all --deny-warn
moon build --target all
moon test --target native
moon fmt --check
```

CI 会构建并测试 native、wasm 和 js 目标；native 是首选目标。生成密钥或随机值的操作需要平台熵源，实际可用性取决于运行环境。

## 安全与限制

- 导入时会验证当前支持的密钥签名，包括 User ID 认证、子钥绑定和 v6 直接密钥签名。这不等于身份或第三方信任验证；应用仍需自行建立对密钥的信任。
- Ed25519 和 X25519 的域运算基于 `@bigint`，不是常数时间实现。垃圾回收运行时也无法保证私钥内存被清零。
- 解密不可信的 Argon2 保护数据时，默认内存上限为 256 MiB。超过上限的请求会在分配前拒绝；API 允许时可由调用方选择其他上限。
- v2 SEIPD 加密 API 不添加填充，因此消息会泄露明文长度的大致范围。
- 不提供平台时钟的目标会关闭过期时间检查，且无法判断吊销日期；吊销签名仍会进行密码学验证。示例 SMTP/IMAP 传输仅支持 native。

依赖与归属声明见 [`THIRD-PARTY-NOTICES.md`](./THIRD-PARTY-NOTICES.md)。
