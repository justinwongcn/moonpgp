# Third-Party Notices / 第三方组件与来源声明

This file records every third-party project that `justinwongcn/moonpgp` (moonpgp)
builds on — runtime dependencies and sources of test material — together with its
license, so the attributions can be carried into any redistribution (mooncakes
publish, GitHub release) or upstream contribution.

本文件记录本项目全部第三方依赖与测试材料来源及其 license。**维护规则：`moon.mod`
依赖变化（新增/升级/移除）时必须同步更新本文件；`moon publish` 前核对一遍。**

## Runtime dependencies（运行时依赖，均已在 `moon.mod` 中固定版本）

| Package | Version | License | Used for（用途） | Repository |
|---|---|---|---|---|
| moonbitlang/core | 0.10.14+7d59c7ec9（随 moon 0.1.20260920 工具链捆绑） | Apache-2.0 | 标准库：`Bytes`/`FixedArray`/`@buffer`、**`@bigint`（Ed25519/X25519 域算术底座）**、`@encoding`（base64/hex/utf8）、`@random`（ChaCha8）、`@env`（平台熵） | https://github.com/moonbitlang/core |
| moonbitlang/x | 0.5.5 | Apache-2.0 | `x/crypto`：SHA 全家桶/MD5/RIPEMD-160/HMAC、**AES-128/192/256 ECB 单块原语**（对称加密路径底座）；`x/fs`：CLI/库传输读文件(FileTransport、netmail) | https://github.com/moonbitlang/x |
| moonbit-community/flate | 0.8.4 | Apache-2.0 | DEFLATE/ZLIB 压缩与解压（`compress` 包的替换点） | https://github.com/moonbit-community/flate |

Ed25519/X25519（RFC 8032/7748）为**本项目自实现**（`pki/curve25519.mbt`，基于 core `@bigint`，
非常数时间——见 README 安全说明），2026-09-30 起不再使用任何第三方公钥算法库；
`moonbitstack/mooncrypt` 已从依赖中移除。

以上 Apache-2.0 包均以独立 mooncakes 包形式引用，**没有任何源码 vendor 进本仓库**；
各包完整 license 文本随包分发，亦可在上表仓库查看。

## Test vectors & reference implementation（测试向量与对标实现）

**ProtonMail gopenpgp v3**（本地快照对应 [v3.4.1]，2026-04-29；`reference/gopenpgp/`）。
用途：功能对标基线（profile/算法范围），且 **`testdata/` 共 46 个文件中有 34 个直接取自
`gopenpgp/crypto/testdata/`**（OpenPGP.js 密钥、`message_signed`、GPG smartcard dummy
等互操作测试向量）。以 MIT 许可分发其测试数据时须随附下列许可文本（原文照录）：

```
(The MIT License)

Copyright (c) 2019 Proton Technologies AG

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
```

Repository: https://github.com/ProtonMail/gopenpgp

**ProtonMail go-crypto v1.4.1**（gopenpgp v3 的 `go.mod` 锁定版本；`reference/gopenpgp/go.mod`）。
用途：Argon2 S2K（S2K type 4）与 usage-253 私钥保护的**双向差分对标**。
`testdata/interop_gocrypto_v4_argon2_key.asc`、`interop_gocrypto_v6_argon2_key.asc`、
`interop_gocrypto_argon2_msg.asc`、`interop_gocrypto_v6_aead_key.asc`、
`interop_gocrypto_v6_aead_msg.asc`、`interop_gocrypto_v6_aead_skesk_msg.asc`
由 go-crypto 自身 writer 生成（Argon2 夹具参数刻意取最小合法值 t=1/p=1/m=2^5 KiB，
口令 `go-crypto-argon2`；v6 AEAD 夹据为 v6 Ed25519+X25519 密钥与 v6 PKESK/SKESK +
v2 SEIPD 消息，口令 `go-crypto-v6`）；生成方式记录在
`testdata/gen_gocrypto_argon2_vectors.md`。go-crypto 以 BSD-3-Clause 许可发布
（Copyright (c) 2009 The Go Authors / Proton AG），分发上述夹具时须随附其许可文本：
https://github.com/ProtonMail/go-crypto/blob/master/LICENSE

## OpenSSL / LibreSSL（经 moonbitlang/async/tls 动态加载，未随包分发）

`example/netmail` 的 TLS 提交（2026-10-06）通过官方包 `moonbitlang/async/tls`
（Apache-2.0）的 native stub 工作。该 stub 运行期 `dlopen` 系统已安装的
SSL 库（macOS 为 `/usr/lib/libssl.*.dylib` 即 LibreSSL；Linux 为
`libssl.so.3`/`libssl.so.1.1` 即 OpenSSL），本项目不重新分发任何 SSL
库的二进制或源码。OpenSSL 本身以 Apache-2.0 许可发布（OpenSSL 3.x）；
LibreSSL 以其自有许可发布，权利归属 OpenSSL Software Services /
LibreSSL 上游作者。使用本库的 TLS 提交功能即默认依赖目标机器的系统
SSL 库，其许可条款随之适用。

## Standards documents（标准文档来源，公有规范，无 license 义务，仅记出处）

测试向量还引用了以下标准中的官方向量：RFC 9580 / RFC 4880（OpenPGP，含附录
A.4 / A.5 / A.8–A.12 的 v6、AEAD 与 Argon2 夹具）、RFC 9106（Argon2，含 §5.3
Argon2id KAT）、RFC 7693（BLAKE2b，附录 A）、RFC 5869（HKDF，附录 A）、
RFC 4493（CMAC-AES，§2.4 全部向量）、RFC 7253（OCB）、RFC 3156（PGP/MIME）、
RFC 3394（AES Key Wrap，附录 B）、RFC 7748（X25519）、RFC 8032（Ed25519）、
FIPS 197 与 NIST SP 800-38A（AES/CFB）、NIST SP 800-38D（GCM）。RFC 文本本身
为 IETF 公有规范。
`primitives/argon2_test.mbt` 中的 x/crypto 向量表取自
`golang.org/x/crypto/argon2`（BSD-3-Clause，Copyright (c) 2017 The Go Authors），
仅作数值引用，未复制其代码。

## 本仓库自生成文件（无第三方权利）

`testdata/` 其余文件（`interop_*.asc` 等）为本地用 GnuPG 2.4.5 生成的无口令测试
密钥与消息，以及 openssl 对拍产物，权利归属本项目；六个
`interop_gocrypto_*` 夹具来源见上文 go-crypto 段落。
`primitives/blake2b.mbt`、`argon2.mbt`、`hkdf.mbt` 均为本项目从 RFC 文本
自实现，未引入新的运行时依赖。

## 本项目许可

moonpgp 本身以 Apache-2.0 许可发布（见 `LICENSE`）。
