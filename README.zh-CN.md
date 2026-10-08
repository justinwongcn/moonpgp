# moonpgp — OpenPGP 邮件加解密（MoonBit 实现）

**模块名：** `justinwongcn/moonpgp` · [mooncakes.io/docs/justinwongcn/moonpgp](https://mooncakes.io/docs/justinwongcn/moonpgp)

用 MoonBit 从零实现的 OpenPGP（RFC 4880/9580）邮件加密/解密/签名/验证库，
对标 ProtonMail gopenpgp v3 的核心能力，为十月份 MoonBit 黑客松而作。

## 安装方式

**环境要求。** MoonBit 工具链 `moon 0.1.20260920` / `moonc
v0.10.14+7d59c7ec9`（moonc 需 0.10.14 及以上）。不需要 C 工具链、不使用 FFI、
不 vendor 任何源码：本库是纯 MoonBit 实现，只依赖 `moonbitlang/x`、
`moonbitlang/async` 与 `moonbit-community/flate`，由 `moon` 自动解析。库目标为
`native`（见 `moon.mod` 的 `preferred_target`）。

**加入已有 MoonBit 项目：**

```bash
moon add justinwongcn/moonpgp
```

然后在该项目的 `moon.pkg` 中声明需要的包：

```text
import {
  "justinwongcn/moonpgp/api",
  "justinwongcn/moonpgp/mime",   // PGP/MIME（RFC 3156）解析与验证
  "justinwongcn/moonpgp/mail",   // RFC 5322 / MIME 组装
}
```

**不写代码直接用 CLI** —— 从本仓库克隆后即可运行：

```bash
git clone https://github.com/justinwongcn/moonpgp
cd moonpgp
moon run cmd/main -- help
```

**克隆后的构建与测试**（与 CI 执行完全一致）：

```bash
moon check --target all --deny-warn
moon build --target all
moon test --target native      # 347 个测试
moon fmt --check
```

## 当前能力（P0 全部完成，P1 全部完成）

| 域 | 内容 |
|---|---|
| ASCII Armor | CRC-24 校验、多块解析、CRLF 容错 |
| 包格式引擎 | RFC 9580 包头（新旧格式、partial length）、PKESK v3+v6、SKESK v4/v5/v6、PublicKey/SecretKey/SecretSubkey（v4+v6）、UserID、Signature v4+v6（子包解析）、OnePassSig v3+v6、Literal、Padding、Compressed、SEIPD v1+MDC 与 v2 |
| 对称加密 | AES-128/192/256、OpenPGP-CFB（resync 与 no-resync 两种变体）、MDC 完整性，以及 **v2 SEIPD 分块 AEAD 层**（salt + HKDF 消息密钥/IV、`0xD2` 头、分块 AD、末块长度绑定 tag） |
| S2K | Simple / Salted / Iterated+Salted（SHA-256/SHA-1/RIPEMD-160/MD5）与 **Argon2（type 4，RFC 9580 §3.7.1.4）** |
| Argon2 原语 | `primitives` 自实现 **BLAKE2b**（RFC 7693）、**Argon2id**（RFC 9106，v=0x13）与 **HKDF-SHA256**（RFC 5869）；解析不可信报文时默认 256 MiB 内存策略，超限在分配前拒绝 |
| RSA | PKCS#1 v1.5 加解密、签名、验证；密钥生成（Miller-Rabin、CRT、扩展欧几里得模逆） |
| Ed25519 | EdDSA legacy（算法 22）签名/验证、密钥生成（自实现 @bigint 算术，`pki/ed25519.mbt`） |
| ECDH / X25519 | **X25519 v6（算法 25）**原生密钥封装/解封：HKDF-SHA256（`info = "OpenPGP X25519"`）+ AES-128 Key Wrap，v6 PKESK 按指纹寻址；Curve25519Legacy（算法 18）X25519 + SHA-256 KDF（§11.4）+ AES Key Wrap（RFC 3394）与 PKESK v3 临时点格式 |
| AEAD 模式 | OCB（RFC 7253，MTI）、EAX、GCM（RFC 9580 §5.13.3–5.13.5），三种模式均可用于 v2 SEIPD、v5/v6 SKESK 与 usage-253 私钥 |
| 密钥管理 | 传输型密钥组装/解析、自签名与子钥绑定签名的创建与验证、口令锁定/解锁（usage 254 CFB，以及 **usage 253 AEAD + HKDF**，支持 Argon2id 或 iterated S2K）、armor 导入导出、keyring |
| 签名/验证 | inline（v4 密钥用 OnePassSig v3，v6 密钥用携带相同 hash salt 与 32 字节指纹的 v6 OPS）、detached、cleartext（§7 规范化）、文本模式 CRLF 规范化 |
| 压缩 | Compressed 包：ZIP（raw DEFLATE）/ZLIB/无压缩，解压端完整支持动态哈夫曼 |
| MIME | PGP/MIME（RFC 3156）：multipart/signed 构建+验证、multipart/encrypted 解析、RFC 5322 头解析 |
| v6 消息加密 | v6 PKESK + **v2 SEIPD**（面向 v6 X25519 子钥）、v6 SKESK + v2 SEIPD（口令），并遵循接收方 Preferred AEAD Ciphersuites；`generate_ed25519_v6_key` 现在同时生成带 v6 绑定签名的 X25519 加密子钥 |
| 顶层 API | `pgp().encryption()/decryption()/key_generation()` builder、KeyRing |

## 互操作验证（全部实测通过）

- **GnuPG 2.4.5 双向互通**：
  - `gpg --symmetric` 的消息我们能解；我们的消息 gpg 能解；
  - 我们生成的 RSA 密钥 gpg 导入成功（主键 [SC] + 子钥 [E]），gpg 用它加密我们能解，我们加密 gpg 能解；
  - **Ed25519（EdDSA legacy）双向**：我们的 Ed25519 签名 gpg 验出 `Good signature`，gpg 识别我们的 Ed25519+cv25519 密钥为 `pub ed25519 [SC] / sub cv25519 [E]`；gpg 的 Ed25519 签名（detached + cleartext，SHA-512）我们能验证；
  - **ECDH（Curve25519Legacy）双向**：gpg 加密到我们 cv25519 子钥的消息我们能解；我们加密到 gpg cv25519 子钥（X25519 + SHA-256 KDF + RFC 3394 key wrap）gpg 能解（`encrypted with cv25519 key`）；
  - gpg 验证我们的 RSA/Ed25519 签名（Good signature），我们验证 gpg 的签名。
- **openssl 3.x**：RSA-2048 签名逐字节复现、openssl 加密的密文我们解密。
- **ProtonMail gopenpgp testdata**：解锁 OpenPGP.js 私钥（口令 "apple"）、解密
  `message_signed` → `message_plaintext`、验证其 v4 自签名、解析 GPG smartcard dummy 密钥。
- **go-crypto v1.4.1（gopenpgp v3 锁定的版本）**：我们能解锁它写出的 v4/v6 私钥
  （Argon2id + AES-256/OCB + HKDF，usage 253）、解密其 Argon2 S2K 消息，以及
  **v6 PKESK + v2 SEIPD** 与 **v6 SKESK + v2 SEIPD** 消息（夹具与生成脚本见
  `testdata/gen_gocrypto_argon2_vectors.md`）；反方向上，go-crypto 程序能解锁本库
  锁定的 v4/v6 密钥、解密本库的 v4/v6 Argon2 消息与 v6 消息，并验证本库的 v6 内联签名。
- **RFC 9580 附录 A.8–A.11**：四条完整的 v6 消息序列（X25519+OCB、EAX、OCB、GCM）
  均解出 "Hello, world!"；`cipher/seipd_v2_test.mbt` 还逐字节核对了 A.8/A.9/A.10
  的 HKDF 输出。
- **RFC 4493 CMAC / RFC 9106 §5.3 / RFC 7693 / RFC 5869**：全部新原语的已知答案测试，
  包含内存不是 `4*parallelism` 整数倍的 Argon2 参数与超过 64 字节的 tag。
- **RFC 9580 附录 A.12/A.5**：三个 A.12 SKESK 消息（AES-128/192/256，Argon2 t=1 p=4 m=2^21）
  均解出 "Hello, world!"；A.5 的 v6 Ed25519 私钥能用口令解锁并签名。两者每次派生需 2 GiB，
  默认 `#skip`，用 `moon test api --target native --include-skipped --filter 'slow:*'` 运行。
- **RFC 9106 / RFC 7693 / RFC 5869 已知答案测试**：含 secret 与 AD 的 Argon2id KAT、
  x/crypto 向量表、全部 BLAKE2b 参考向量、三个 HKDF 附录 A 用例。
- openssl AES-CFB 生成的 SEIPD v1 已知答案向量；AES Key Wrap 采用 RFC 3394 附录 B 官方向量。

一条命令跑完整 GnuPG 互验矩阵（六个方向，每次全新密钥）：

```bash
./scripts/interop_check.sh
```

自动化测试：`moon test --target native`（347 个测试，含上述全部向量；两个 RFC 9580
Argon2 夹具因每次派生需 2 GiB 而默认 `#skip`，用 `--include-skipped --filter 'slow:*'` 运行）。
`moon test --target wasm` 与 `--target js` 各运行 339 个测试。wasm-gc 无平台熵源：
不含熵的测试仍通过，但 100 个需要生成密钥材料（keygen、随机 IV/salt、Argon2）的用例
会以 `platform entropy source unavailable` 失败；完整套件请用 native / wasm / js。

## 快速上手（CLI 演示）

```bash
moon run cmd/main -- keygen "Demo <demo@example.com>" sec.asc pub.asc      # RSA 密钥（默认 3072 位）
moon run cmd/main -- edkeygen "Demo <demo@example.com>" sec.asc pub.asc    # Ed25519 + cv25519 密钥
moon run cmd/main -- encpass "口令" 明文.txt msg.asc                        # 口令加密
moon run cmd/main -- decpass "口令" msg.asc 还原.txt                        # 口令解密
moon run cmd/main -- encpub pub.asc 明文.txt msg2.asc                       # 公钥加密（RSA/ECDH 自适应）
moon run cmd/main -- decpriv sec.asc msg2.asc 还原2.txt                     # 私钥解密
moon run cmd/main -- sign sec.asc 明文.txt sig.asc                          # 分离签名
moon run cmd/main -- verify pub.asc 明文.txt sig.asc                        # 验签
```

## 库用法

```moonbit nocheck
// 口令加密/解密

///|
let armored = @api.encrypt_with_password(plaintext, "passphrase")

///|
let plain = @api.decrypt_with_password(armored, "passphrase")

// 密钥生成 + 公钥加密/私钥解密

///|
let key = @api.generate_key("Alice <alice@example.com>")

///|
let armored = @api.encrypt_to_recipients(data, [key.to_public()])

///|
let plain = @api.decrypt_with_private_key(armored, key)

// Argon2 S2K（RFC 9580 §3.7.1.4，specifier type 4）——RFC 推荐的口令 KDF，
// 默认参数与 gopenpgp RFC 9580 profile 一致（t=3、p=4、m=2^16 KiB）；
// unlock() 同时处理 usage 253 与 254。

///|
let locked = key.lock_argon2("口令", memory_exp=16)

///|
let unlocked = locked.unlock("口令")

///|
let armored = @api.encrypt_with_password_argon2(plaintext, "口令")

///|
let plain = @api.decrypt_with_password(armored, "口令")

// gopenpgp 风格 builder

///|
let encrypt = @api.pgp().encryption().password("pw").finish()

///|
let decrypt = @api.pgp().decryption().password("pw").finish()
```

### 邮件演示管线（`example/`,不属于库 API）

库的邮件能力是**组装（`mail`）+ 解析验签（`mime`）**两半。线上传输——
POSIX socket SMTP 客户端、IMAP4rev1 子集客户端（`example/netmail`）与两个
CLI 演示（`example/mailer`、`example/mailreader`）——是**演示与测试基建**,
不作为发布 API：它们的存在是为了端到端验证库本身（一封签名+加密邮件经
SMTP 提交、再经 IMAP 取回、解密验签,一条命令闭环——`example/mailer/e2e.sh`、
`example/mailer/e2e_tls.sh` 与 `example/mailreader/e2e.sh`）。

它们是功能完整的（已对真实 163 邮箱与 Proton 对端完成过互联网往返）,但有
意保持边界：仅 native 目标（TLS 提交基于 POSIX socket + `moonbitlang/async/tls`
阻塞门面）,支持隐式 TLS(465)与 STARTTLS(587),信任策略为系统根证书或
证书钉扎,IMAP 仅 INBOX,明文连非本地主机需显式 opt-in。见安全声明。

## 模块布局（可替换性设计）

```
primitives/  # 隔离层：唯一的第三方 crypto 接入点；BlockCipher trait、HashId、熵源断言
armor/       # CRC-24 + armor（PGP 专属，永不替换）
s2k/         # S2K（PGP 专属，永不替换）
packet/      # 包格式引擎（PGP 专属，永不替换）
cipher/      # OpenPGP-CFB 变体 + SEIPD v1/MDC + AES Key Wrap（RFC 3394）
pki/         # RSA（keygen/PKCS#1 v1.5）、Ed25519/X25519（RFC 8032/7748 自实现，`curve25519.mbt`）
compress/    # DEFLATE/ZLIB（当前走 moonbit-community/flate，可替换点）
mime/        # PGP/MIME（RFC 3156）：解析、验签、收件交付
mail/        # RFC 5322 邮件组装（头、QP/7bit 策略、附件）——不含传输
api/         # 密钥管理、签名、ECDH/RSA 会话密钥封装、keyring、builder
interop/     # 与 gopenpgp/GnuPG/openssl 的互通测试
```

库包直接位于仓库根目录，因此 import 路径 = 模块名 + 包名
（`justinwongcn/moonpgp/api`），不经过任何中间目录层。支撑材料放在 `cmd/`
（演示 CLI）、`example/`（传输与 mailer/mailreader 演示）与 `testdata/`
（夹具），属演示与测试基建，不属于发布出去的库 API——见上文"邮件演示管线"。

依赖（版本固定）：`moonbitlang/x@0.5.5`（哈希全家桶/HMAC/AES-ECB 单块原语）、
`moonbit-community/flate@0.8.4`（DEFLATE）。Ed25519/X25519 按 RFC 8032/7748 基于
core `@bigint` 自实现（`pki/curve25519.mbt`），公钥路径无第三方依赖。
替换任何一个 = 改 `primitives`（或对应模块）里的一个 adapter 文件 + 全量向量回归。

第三方依赖与测试向量来源（含 gopenpgp MIT 归属声明）的完整清单见
[THIRD-PARTY-NOTICES.md](./THIRD-PARTY-NOTICES.md)。

## 安全说明（如实陈述）

- 所有密钥/会话密钥/素数随机数经 `@env.rand` 平台熵源断言获取，**不存在固定种子回退**。
- RSA 密钥生成使用 40 轮随机基 Miller-Rabin + 小素数试除；默认 3072 位。
- Ed25519/X25519 的 `@bigint` 域算术**非常数时间**（与 RSA 同类限制）；如需抗时序侧信道的
  高价值场景，请替换为常数时间实现（`pki/curve25519.mbt` 是隔离点）。
- GC 语言无法真正清零私钥内存；`Cipher::wipe`/密钥清零是尽力而为。
- 支持解密侧的 v3 遗留特性有限；生成端默认产出 v4 格式。RFC 9580 v6 Ed25519
  签名密钥/签名与 AEAD（OCB/GCM）消息形态已实现（v6 仅分离签名；AEAD 为
  对称密钥/tag-20 形态，用于 GnuPG `--force-aead` 互通——新键消息仍走 SEIPD v1）。
  **Argon2 S2K（type 4）、usage 253 私钥保护（Argon2 + HKDF-SHA256 + AES-256/OCB）、
  v6 PKESK/SKESK 与 v2 SEIPD 消息加解密均已实现**；Ed448/X448 与 v5 密钥不在范围内。
- **Argon2 内存由攻击者控制**：20 字节 S2K specifier 最多可要求 2^31 KiB，且派生发生在
  任何认证**之前**。解析不可信报文的入口（`decrypt_with_password`、
  `decrypt_binary_with_password`、`PrivateKey::unlock`）默认
  `DEFAULT_ARGON2_MAX_MEMORY_KIB` = 256 MiB，超限时**在分配之前**直接失败——这是主流实现
  写出默认 64 MiB 档的 4 倍，也低于实现硬顶 `ARGON2_MAX_MEMORY_KIB`（2 GiB，RFC 9106 首选档，
  RFC 9580 附录 A.5/A.12 使用的值）8 倍。要打开这类报文必须显式放宽：
  `decrypt_with_password(msg, pass, argon2_max_memory_kib=@primitives.ARGON2_MAX_MEMORY_KIB)`
  ——`scripts/acceptance.sh` 正是这样跑 A.5/A.12 的。量级参照：OpenPGP.js 默认上限 1 TiB，
  go-crypto/gopenpgp 不设上限。
- **不验证证书/自签名**：密钥解析只做结构校验。v6 密钥必须*带有* Direct Key 签名
  （RFC 9580 §5.2.3.10），但**不做**密码学验证；算法偏好、有效期与吊销信息按签名
  原样读取。这与本库对标的 gopenpgp/go-crypto 一致（它同样只"选取"自签名而不验签）；
  需要信任的应用必须自行验证密钥——参见 `gpg --check-sigs`、OpenPGP.js
  `verifyPrimaryKey`、Sequoia `Cert::with_policy`。
- 非 native 后端（wasm/js）暂无时钟 API，密钥创建时间为占位值（见 `primitives/clock.mbt`）。
- 演示传输（`example/netmail`）仅 native 目标。SMTP 提交默认加密（465 隐式 TLS /
  587 STARTTLS,对系统根证书校验）;`--smtp-trust pem:FILE` 钉扎对端证书
  （DER 精确比对）,`--smtp-trust none` 仅显式 opt-in 并打印显著警告。明文连接
  拒绝非 localhost 的 AUTH,IMAP 明文连非本地主机需显式 `allow_insecure`。
  无 TLS 可用时仍可把 .eml 交给 MTA（msmtp）。明文暴露的只有凭据与元数据——
  邮件内容保持端到端加密。

## P1/P2 路线

- P1 全部完成：✅ cleartext 签名（与 gpg 互验）、✅ PGP/MIME（RFC 3156 构建/解析，与 gpg 互验）、✅ DEFLATE、✅ Ed25519（签名/验证/密钥生成，与 gpg 双向互验）、✅ ECDH Curve25519Legacy 加密端（X25519 + KDF + key wrap，与 gpg 双向互验）。
- v6 + AEAD（2026-10-08）：RFC 9580 v6 Ed25519 分离签名与 v6 密钥/指纹
  （与 go-crypto v1.4.1 及 mizchi `pgp` 参考包双向对拍）；另自写 OCB3（RFC 7253）
  与 GCM，落地 4880bis tag-20 分块层与 v5 SKESK（`encpass ... aead`），
  与 gpg `--force-aead` 双向字节级互操作（`scripts/interop_aead_gpg.sh`）。
- 赛后路线：Argon2 S2K（计划自实现 BLAKE2b + Argon2id）、SEIPD v2 与 v6 消息加密
  （v6 子钥、v6 one-pass 签名）、DEFLATE 自实现（替换 moonbit-community/flate，
  differential test 方案）。

新增能力（P1）：

```moonbit nocheck
// cleartext 签名（RFC 9580 §7）
let msg = @api.sign_cleartext("文本\n", key)
let (text, status) = @api.verify_cleartext(msg, key.to_public())

// PGP/MIME（RFC 3156）
let mime_msg = @mime.build_pgp_mime_signed("正文\n", key)
let (text, status) = @mime.verify_pgp_mime_signed(mime_msg, key.to_public())
let payload = @mime.extract_pgp_encrypted(mime_msg)   // 取出 PGP MESSAGE

// Ed25519 主钥（EdDSA legacy，算法 22）+ Curve25519Legacy ECDH 加密子钥
// —— gopenpgp "Default" profile 形态，gpg 实测双向互通
let key = @api.generate_ed25519_key("Ed <ed@example.com>")
```
