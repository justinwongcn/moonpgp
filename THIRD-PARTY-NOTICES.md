# Third-Party Notices / 第三方组件与来源声明

This file records the third-party projects that `justinwongcn/moonpgp` (moonpgp)
uses at runtime and the external material used for interoperability tests,
together with the applicable licenses and attributions.

本文件记录本项目全部第三方运行时依赖、测试材料来源及其许可证。维护规则：
`moon.mod` 依赖变化（新增、升级、移除）或 `testdata/` 来源变化时必须同步更新本文件；
`moon publish` 前核对一遍。

## Runtime dependencies（运行时依赖）

| Package | Version | License | Used for（用途） | Repository |
|---|---|---|---|---|
| moonbitlang/core | 0.10.16+b1a0e846e（moon 0.1.20261020 工具链自带，不在 `moon.mod` 中） | Apache-2.0 | 标准库：`Bytes`/`FixedArray`/`@buffer`、`@bigint`（Ed25519/X25519 域算术底座）、`@encoding`（base64/hex/utf8）、`@random`（ChaCha8）、`@env`（平台熵） | https://github.com/moonbitlang/core |
| moonbitlang/x | 0.5.5 | Apache-2.0 | `x/crypto`：SHA 全家桶/MD5/RIPEMD-160/HMAC、AES-128/192/256 ECB 单块原语（对称加密路径底座）；`x/fs`：CLI/库传输读文件（FileTransport、netmail） | https://github.com/moonbitlang/x |
| moonbit-community/flate | 0.8.4 | Apache-2.0 | DEFLATE/ZLIB 压缩与解压（`compress` 包的替换点） | https://github.com/moonbit-community/flate |
| moonbitlang/async | 0.22.4 | Apache-2.0 | 异步运行时与传输：`async/io`/`async/socket`/`async/tls`（example/netmail 的异步 SMTP/IMAP 与 TLS 提交）、mailer 的 `async fn main`（示例/演示层，非库 API） | https://github.com/moonbitlang/async |

`moonbitlang/x`、`moonbit-community/flate`、`moonbitlang/async` 在 `moon.mod` 中固定版本；
`moonbitlang/core` 由 MoonBit 工具链提供。x/flate/async 以独立 mooncakes 包解析，
core 随工具链分发；本仓库没有 vendor 任何依赖源码，各项目的许可证原文见上表仓库及其
发行物。

`moonbitlang/core` 自带 `NOTICE`，其中包含 IDEA、V8/fdlibm、Go `math/big`、musl、
FreeBSD 等组件的归属声明。本仓库只引用 core 包；如果再分发包含 core 的编译产物，
需同时携带该 `NOTICE` 的原文（工具链中的 `$MOON_HOME/lib/core/NOTICE`，或上游仓库的
同名文件）。

Ed25519/X25519（RFC 8032/7748）为**本项目自实现**（`pki/curve25519.mbt`，基于 core
`@bigint`，非常数时间——见 README 安全说明），2026-09-30 起不再使用任何第三方公钥
算法库；`moonbitstack/mooncrypt` 已从依赖中移除。

## Test vectors & reference implementation（测试向量与对标实现）

### ProtonMail gopenpgp v3.4.1（MIT）

本地参考快照 `reference/gopenpgp/` 对应 gopenpgp v3.4.1（2026-04-29），用作功能对标
基线；`.moonignore` 已将其排除出发布包。当前 `testdata/` 中有 41 个文件与
`gopenpgp/crypto/testdata/` 字节一致：34 个顶层文件，以及 `signature/` 下的 7 个文件。
这些夹具覆盖 OpenPGP.js 密钥、`message_signed`、GPG smartcard dummy 等互操作场景。
以 MIT 许可分发这些测试数据时需随附以下许可文本（原文照录）：

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

### ProtonMail go-crypto（BSD-3-Clause）

源码仓库中的 `testdata/gocrypto/` 是一个独立的 Go 模块，锁定
`github.com/ProtonMail/go-crypto v1.5.2`，用于生成 6 个
`testdata/interop_gocrypto_*.asc` 互操作夹具。gopenpgp v3.4.1 自身锁定的是 go-crypto
v1.4.1（见 `reference/gopenpgp/go.mod`）；v1.4.1 也经过编译验证，在相同输入上生成的
夹具结构与 v1.5.2 一致，但仓库中提交的夹具和生成器锁定版本均为 v1.5.2。v1.4.1 与
v1.5.2 的 LICENSE 文件内容相同，BSD-3-Clause 原文如下（原文照录）：

```
Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

生成/校验工具见源码仓库中的 `testdata/gocrypto/`；夹具的生成参数和校验记录见
`testdata/gen_gocrypto_argon2_vectors.md`。

### golang.org/x/crypto（BSD-3-Clause）

`primitives/argon2_test.mbt` 的 Argon2id 向量表取自 `golang.org/x/crypto/argon2`
v0.41.0（源码仓库中 `testdata/gocrypto` 生成器模块的间接依赖）。这里只引用数值向量，
没有复制其源代码；源文件头标注 Copyright 2017 The Go Authors，许可证文件为
BSD-3-Clause（Copyright 2009 The Go Authors），原文如下（原文照录）：

```
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## OpenSSL / LibreSSL（经 moonbitlang/async/tls 动态加载，未随包分发）

`example/netmail` 的 TLS 提交功能通过 `moonbitlang/async`（Apache-2.0）的 native stub
调用系统 SSL 库：macOS 为 `/usr/lib/libssl.*.dylib`（LibreSSL），Linux 为
`libssl.so.3` / `libssl.so.1.1`（OpenSSL）。本仓库不重新分发 OpenSSL 或 LibreSSL 的
源码或二进制。OpenSSL 3.x 使用 Apache-2.0；LibreSSL 的许可条款见其上游发行版
（OpenBSD 项目）。使用该功能时需要自行确认目标机器上 SSL 库的许可证。

## Standards documents（标准文档来源）

测试向量还引用了以下标准中的官方向量：RFC 9580 / RFC 4880（OpenPGP，含附录
A.4 / A.5 / A.8–A.12 的 v6、AEAD 与 Argon2 夹具）、RFC 9106（Argon2，含 §5.3
Argon2id KAT）、RFC 7693（BLAKE2b，附录 A）、RFC 5869（HKDF，附录 A）、RFC
4493（CMAC-AES，§2.4 全部向量）、RFC 7253（OCB）、RFC 3156（PGP/MIME）、
RFC 3394（AES Key Wrap，附录 B）、RFC 7748（X25519）、RFC 8032（Ed25519）、
FIPS 197 与 NIST SP 800-38A（AES/CFB）、NIST SP 800-38D（GCM）。

RFC 文档由 IETF 发布，文本使用受 IETF Trust 条款约束；本项目只引用其中的算法参数和
测试数据，不复制 RFC 正文。

## 本仓库自生成文件与测试数据

截至 2026-10-22，源码仓库的 `testdata/` 共 74 个文件：

- 41 个与 gopenpgp v3.4.1 的 `crypto/testdata/` 字节一致（34 个顶层文件 + 7 个
  `signature/` 文件）；
- 6 个 `interop_gocrypto_*.asc` 由 ProtonMail go-crypto v1.5.2 生成；
- `testdata/gocrypto/` 下 7 个文件是本项目的夹具生成/校验工具（生成器、校验器、
  go.mod/go.sum 等；Go 模块依赖 go-crypto，但未复制其源码）；该目录通过
  `.moonignore` 排除出发布包，6 个 `.asc` 夹具仍随包分发；
- 其余 20 个为本项目自建：GnuPG 2.4.5 / OpenSSL 生成的互操作夹具、本项目实现生成
  的夹具，以及生成脚本和说明。

`primitives/blake2b.mbt`、`argon2.mbt`、`hkdf.mbt` 均为按 RFC 自实现，未引入新的
运行时依赖。

## 本项目许可

moonpgp 以 Apache-2.0 许可发布，见 `LICENSE` 与 `NOTICE`。第三方组件仍适用各自的
许可证；本项目的许可证不改变这些条款。

发布包通过 `.moonignore` 排除 `cert.rs`、`reference/`、`docs/` 和
`testdata/gocrypto/`；`testdata/` 中的夹具、`LICENSE`、`NOTICE` 与本文件随
`moon package` / `moon publish` 分发。`cert.rs` 是 Sequoia PGP 的本地参考代码
（LGPL-2.0-or-later），仅用于阅读，不入库也不发布。
