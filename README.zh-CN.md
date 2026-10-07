# moonpgp — OpenPGP 邮件加解密（MoonBit 实现）

用 MoonBit 从零实现的 OpenPGP（RFC 4880/9580）邮件加密/解密/签名/验证库，
对标 ProtonMail gopenpgp v3 的核心能力，为国产开源生态大赛 OSC 2026 而生。

## 当前能力（P0 全部完成，P1 全部完成）

| 域 | 内容 |
|---|---|
| ASCII Armor | CRC-24 校验、多块解析、CRLF 容错 |
| 包格式引擎 | RFC 9580 包头（新旧格式、partial length）、PKESK v3、SKESK v4、PublicKey/SecretKey、UserID、Signature v4（子包解析）、OnePassSig、Literal、Compressed、SEIPD v1+MDC |
| 对称加密 | AES-128/192/256、OpenPGP-CFB（resync 与 no-resync 两种变体）、MDC 完整性 |
| S2K | Simple / Salted / Iterated+Salted（SHA-256/SHA-1/RIPEMD-160/MD5） |
| RSA | PKCS#1 v1.5 加解密、签名、验证；密钥生成（Miller-Rabin、CRT、扩展欧几里得模逆） |
| Ed25519 | EdDSA legacy（算法 22）签名/验证、密钥生成（自实现 @bigint 算术，`pki/ed25519.mbt`） |
| ECDH | Curve25519Legacy（算法 18）会话密钥封装/解封：X25519 + SHA-256 KDF（§11.4）+ AES Key Wrap（RFC 3394），PKESK v3 临时点格式 |
| 密钥管理 | 传输型密钥组装/解析、自签名与子钥绑定签名的创建与验证、口令锁定/解锁（usage 254）、armor 导入导出、keyring |
| 签名/验证 | inline（OnePassSig）、detached、cleartext（§7 规范化）、文本模式 CRLF 规范化 |
| 压缩 | Compressed 包：ZIP（raw DEFLATE）/ZLIB/无压缩，解压端完整支持动态哈夫曼 |
| MIME | PGP/MIME（RFC 3156）：multipart/signed 构建+验证、multipart/encrypted 解析、RFC 5322 头解析 |
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
- openssl AES-CFB 生成的 SEIPD v1 已知答案向量；AES Key Wrap 采用 RFC 3394 附录 B 官方向量。

一条命令跑完整 GnuPG 互验矩阵（六个方向，每次全新密钥）：

```bash
./scripts/interop_check.sh
```

自动化测试：`moon test`（246 个测试，含上述全部向量；wasm 目标 238 个）。

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

// gopenpgp 风格 builder

///|
let encrypt = @api.pgp().encryption().password("pw").finish()

///|
let decrypt = @api.pgp().decryption().password("pw").finish()
```

### 邮件演示管线（`example/`,不属于库 API）

库的邮件能力是**组装（`src/mail`）+ 解析验签（`src/mime`）**两半。线上传输——
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
src/
├── primitives/  # 隔离层：唯一的第三方 crypto 接入点；BlockCipher trait、HashId、熵源断言
├── armor/       # CRC-24 + armor（PGP 专属，永不替换）
├── s2k/         # S2K（PGP 专属，永不替换）
├── packet/      # 包格式引擎（PGP 专属，永不替换）
├── cipher/      # OpenPGP-CFB 变体 + SEIPD v1/MDC + AES Key Wrap（RFC 3394）
├── pki/         # RSA（keygen/PKCS#1 v1.5）、Ed25519/X25519（RFC 8032/7748 自实现，`curve25519.mbt`）
├── compress/    # DEFLATE/ZLIB（当前走 moonbit-community/flate，可替换点）
├── mime/        # PGP/MIME（RFC 3156）：解析、验签、收件交付
├── mail/        # RFC 5322 邮件组装（头、QP/7bit 策略、附件）——不含传输
├── api/         # 密钥管理、签名、ECDH/RSA 会话密钥封装、keyring、builder
└── interop/     # 与 gopenpgp/GnuPG/openssl 的互通测试
```

线上传输与 CLI 演示在 `example/`（netmail、mailer、mailreader）,属演示与
测试基建——见上文"邮件演示管线"。

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
  Argon2 S2K 仍在路线图上。
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
