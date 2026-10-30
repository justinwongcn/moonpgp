# moonpgp

用 MoonBit 写的 OpenPGP 库，可以做消息加解密、签名、密钥管理，也支持 PGP/MIME 邮件。

**模块：** `justinwongcn/moonpgp` · [包文档](https://mooncakes.io/docs/justinwongcn/moonpgp) · [![CI](https://github.com/justinwongcn/moonpgp/actions/workflows/ci.yml/badge.svg)](https://github.com/justinwongcn/moonpgp/actions/workflows/ci.yml)

[English documentation](./README.mbt.md)

## 安装

需要 MoonBit 工具链，依赖交给 `moon` 解析：

```bash
moon add justinwongcn/moonpgp
```

请用 0.2.0 或更高版本：0.1.0 受已知的子键注入漏洞影响（见 [SECURITY.md](SECURITY.md)）。`moon add` 默认解析到最新发布版。

根包是主要 API；要解析 PGP/MIME 或组装 RFC 5322 邮件，再单独导入 `mime` 和 `mail`：

```text
import {
  "justinwongcn/moonpgp",
  "justinwongcn/moonpgp/mime",
  "justinwongcn/moonpgp/mail",
}
```

根包把 `@api` 的函数和选项类型以 `@moonpgp.*` 的形式导出。

## 接口速览

生成一把密钥、加密、再解开。下面的代码块会被 `moon test` 编译并执行，不会与代码脱节：

```mbt check
test "a tiny round trip" {
  let key = @moonpgp.generate_ed25519_key("alice@example.com")
  let armored = @moonpgp.pgp().encryption().recipient(key.to_public()).finish()(
    b"hi, from the README",
  )
  let open = @moonpgp.pgp().decryption().decryption_key(key).finish()
  match open(armored) {
    Data(data) => assert_eq(data, b"hi, from the README")
    Verified(data) => assert_eq(data, b"hi, from the README")
    SignatureError(_) => fail("unexpected signature error")
  }
}
```

错误是带类型的：口令错误抛 `WrongPassphrase`，输入损坏抛 `Malformed`，未实现的算法抛 `Unsupported`——都从根包直接可用：

```mbt check
test "wrong passphrases are a typed error" {
  let key = @moonpgp.generate_ed25519_key("alice@example.com").lock("right")
  try {
    let _ = key.unlock("wrong")
    fail("unlocking must fail")
  } catch {
    WrongPassphrase(_) => () // 预期的失败类别
    _ => fail("expected WrongPassphrase")
  }
}
```

生成与校验分离签名：

```mbt check
test "detached signatures and verification" {
  let signer = @moonpgp.generate_ed25519_key("signer@example.com")
  let data = b"release tarball bytes or document payload"
  let sig = @moonpgp.sign_detached(data, signer)
  let status = @moonpgp.verify_detached(data, sig, signer.to_public())
  assert_eq(status, @moonpgp.VerifyStatus::Ok)
}
```

处理 PGP/MIME 邮件时，导入 `"justinwongcn/moonpgp/mime"`：

```mbt check
test "pgp/mime sign and verify" {
  let key = @moonpgp.generate_ed25519_key("mime@example.com")
  let message = @mime.build_pgp_mime_signed("Hello from MoonBit\n", key)
  let (_, status) = @mime.verify_pgp_mime_signed(message, key.to_public())
  assert_eq(status, @api.Ok)
}
```

仓库里还带一个命令行示例，克隆下来就能跑：

```bash
git clone https://github.com/justinwongcn/moonpgp
cd moonpgp
moon run cmd/main -- help
```

## 功能

- **密钥：** 生成、导入、导出、口令加锁和解锁。支持 RSA、Ed25519（旧版 EdDSA）和 Curve25519/X25519；新建密钥默认 v4，v6 也能用——`generate_ed25519_v6_key_with_signing_subkey` 一键生成 v6 的 gpg 双子键形状：仅认证主键、X25519 加密子键、带 v6 交叉认证的 Ed25519 签名子键。绑定的子键全部保留，各自按自己的 key flags 判断用途；能力、过期、吊销状态都有检查函数。证书还能就地生长和调整：吊销主键或单个子键、签出独立的 `.rev` 证书存档备用（gpg `--gen-revoke` 生成的证书同样可以应用）、给既有密钥添加新的加密或签名子键、在生成时或之后设置与延长过期（`KeyGenBuilder::expires`、`set_expiry`、`set_subkey_expiry`），以及管理身份（`add_user_id`、`revoke_user_id`、`set_primary_user_id`）。
- **消息：** 公钥或口令加密，分离/内联/明文签名，会话密钥操作，输出压缩用 ZIP/ZLIB。解密侧连 BZip2 也认——gpg 在 `--compress-algo bzip2` 下发出的消息可以直接打开，纯 MoonBit 解码器逐块校验 block 与流 CRC。文档签名按能力选组件：主键可签就用主键，否则用签名子键（其绑定签名带 gpg 要求的交叉认证）。本库加密输出一律用 AES；CAST5 和 3DES 只用于解密。
- **v6 消息：** v6 PKESK/SKESK 和 v2 SEIPD（OCB、EAX、GCM 三种 AEAD）端到端支持；加密 builder 的口令收件人也可以选 v6 形态（`.password_v6`），但 v4 与 v6 形态不能混在一条消息里。常规 v4 收件人和口令流程默认走 v1 SEIPD。
- **口令保护：** 迭代加盐 S2K 和 Argon2，包括配套的 AEAD 私钥保护格式。
- **邮件：** `mime` 解析并验证 PGP/MIME；`mail` 组装 RFC 5322 邮件，含签名和加密的 PGP/MIME。`example/` 下的 SMTP/IMAP 客户端只是示例，不算库 API，而且只能在 native 上跑。

## 互操作与本地检查

测试覆盖了部分与 GnuPG、OpenSSL、go-crypto 的互操作流程，另有 RFC 测试向量。GnuPG 检查脚本在 [`scripts/interop_check.sh`](./scripts/interop_check.sh)，由 CI 每晚定时运行（推送流水线则内置 GnuPG 产出的冻结向量）。

本地检查：

```bash
moon check --target all --deny-warn
moon build --target all
moon test --target native
moon fmt --check
```

CI 覆盖 native、wasm、js 三个目标，日常开发建议直接用 native。生成密钥这类依赖随机数的操作需要平台熵源，不是每个运行环境都有。

## 安全与限制

- 导入时会校验它认识的签名（User ID 认证、子钥绑定、v6 直接签名），但校验签名不等于建立信任：密钥是否真的属于某个人，要由应用自己判断。
- RSA、Ed25519 和 X25519 的域运算基于 `@bigint`，不是常数时间实现；GC 环境下也无法保证私钥内存被清零。
- 解密不可信的 Argon2 数据默认限 64 MiB 内存，超限请求在分配前就会被拒绝；部分 API 允许设置其他上限。
- 加密 API 不给 v2 SEIPD 加填充，密文长度会大致暴露明文长度。
- 没有平台时钟的目标上，过期检查不可用，吊销日期也无法判断；吊销签名本身仍会做密码学验证。

依赖与归属声明见 [`THIRD-PARTY-NOTICES.md`](./THIRD-PARTY-NOTICES.md)。

## 许可证

Apache-2.0，详见 [LICENSE](./LICENSE)、[NOTICE](./NOTICE) 与 [THIRD-PARTY-NOTICES.md](./THIRD-PARTY-NOTICES.md)。
