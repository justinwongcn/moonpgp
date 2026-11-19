# RFC 9580 符合性审计与攻击测试报告(2026-11-19/20)

worktree 分支 `audit-conformance-20261119`(HEAD 3ed41dd 起算)。两条轨道:
①需求驱动的逐条符合性矩阵(此前从未做过);②安全团队式持续攻击测试。
两轮符合性 agent(C1 包格式 / C2 密钥材料与算法)+两轮攻击 agent(X1 中断 /
X2 终局),探针与红收据随修随转正。

## 总量

- C1(§4-§5.14+§10.3 包格式):33 条款簇,GAP 10(MUST 级 7)+conformant-untested 3
- C2(§3.7-§13.7 密钥材料/算法/S2K/AEAD):约 50 条款簇,GAP 7(MUST 级 7)+
  conformant-untested 3+SHOULD 级文档化偏差 6
- 攻击轮:X1(中断,探针归档 /tmp/audit_x1_probes/)+X2(见下)
- **修复:17 项 MUST 级 GAP 全部落地**,SHOULD 级偏差文档化 8 条

## C1 包格式矩阵(节选,全表见审计 agent 报告)

| # | RFC | GAP | 修复 |
|---|---|---|---|
| C1-G1 | §4.3 | 未知包 criticality 语义缺失:0-39 必须拒序列、40-63 必须忽略,实现一律跳过(tag 21 Padding 豁免) | read_one_packet 加 §4.3 闸(tag 21 豁免) |
| C1-G2 | §5.3.1 | v4 SKESK 解包零 IV 硬编码 16 字节——CAST5/3DES(块 8)历史报文必拒且误分类 WrongPassphrase(M2 孪生漏网) | IV 随包裹密码块长 |
| C1-G3 | §5.2.3.4 | Ed25519 签名可携 <256-bit 摘要(SHA-224)通过验签(MUST reject) | verify 端 digest≥256 闸(key_signing 同) |
| C1-G4 | §5.2.3.35 | Issuer Fingerprint 版本八位组从不与签名版本交叉校验 | 双验证器加版本交叉(F5 夹具适配) |
| C1-G5 | §5.8/§10.3 | Marker 包在解密载荷路径整包失败(MUST ignore) | extract_literal 跳过 Marker |
| C1-G6 | §5.2.5/§10.3.2.2 | OPS↔Signature 配对零校验:v3-OPS+v6 签名照常验证 Ok | collect_data_sig 记录 OPS,Table 27 行配对+字段比对,不符即忽略 |
| C1-G7 | §5.4 | 单签名 OPS 写 nested=0(声明后随另一 OPS) | 生成侧 nested=true |
| C1-G8/G9 | §5.2.3.35/.11/.29 | v4 签名无 Issuer Fingerprint 子包、creation-time/Key-Flags 未标 critical(SHOULD 级) | **登记为文档化偏差**(wire 字节大改+gpg 实践对齐,随 0.5.0 决策) |
| C1-G10 | §5.2.5 等 | pub(all) 直构面版本域(既往 A1 登记) | 维持 0.5.0+ 登记 |

## C2 密钥材料与算法矩阵(节选)

| # | RFC | GAP | 修复 |
|---|---|---|---|
| C2-G1 | §9.5 接收侧 | v6 私钥/v6 SKESK 的 S2K 可携 MD5/SHA-1/RIPEMD-160(MUST NOT decrypt) | lock.mbt+password.mbt 双闸(S2k::uses_weak_hash) |
| C2-G2 | §9.5 生成侧 | sign_cleartext_with 接受 SHA-1/RIPEMD-160 并产出可分发签名(F13 反向钉死) | make_document_signature_with 门扩展+policy_gate 参数(verify 侧测试铸造用) |
| C2-G3 | §12.2/§12.3.1 | v4 收件人加密硬编码 AES-256,从不读 Preferred Symmetric Algorithms | recipient_symmetric_prefs+pick_v4_symmetric(强→弱交集),v1 SEIPD 随选;build_skesk 参数化 |
| C2-G4 | §12.4 接收侧 | RSA <2048 可验签/签名/加密(MUST NOT) | pkcs1 三入口 ≥2048 闸;连带的 rsa1024 互操作夹具全部重造(interop_our_key/two_uid → rsa3072,key_expiredKey 以库铸造 rsa3072+SE 1337s 复刻) |
| C2-G5 | §5.5.3 接收侧 | usage=0 秘钥导入:MPI 不验恰好消费+2-octet 校验和值;native 形不验校验和值 | 五访问器(RSA/EdDSA/ECDH/Ed25519/X25519)全补 |
| C2-G6 | §5.5.5.1 | 生成 RSA 按 p、q 采样原序写出(~50% p>q) | 采样后归一化 p<q |
| C2-G7 | §9.5 验证侧 | SHA-1/RIPEMD-160 签名无论日期一律可验(MUST NOT validate recent) | recent=SHAttered 截止 2020-01-01:之后 Failed,之前 legacy 可验(测试双日期) |

SHOULD 级文档化偏差(C2 报告 §五,6 条):v4 默认生成、Ed448/X448 未实现、
<3072 验签、压缩偏好未消费、v6 私钥 254 保护、SED 不识别——均为登记决策。

## 攻击测试

### X1(预认证面,中断于并发限制)

探针三包归档 /tmp/audit_x1_probes/(packet/keys/armor)。中断前未报告命中;
探针已由 X2 复活重跑(见下)。

### X2(攻击本轮修复边界+复活 X1 归档探针)

32 条合并回归探针(覆盖 C1/C2 全部 17 项修复面:criticality 闸、SKESK IV、
Ed25519 摘要域、issuer-fp 交叉、Marker 跳过、OPS 配对、nested 位、v6 弱哈希
双闸、prefs 选密、RSA 下限、p<q、recent 截止)+X1 归档三包复活重跑。
**已攻未破:32/32 探针按修复后语义保持;X1 复活探针零命中。**

命中 4 项(全部修复,探针翻转为回归断言):

| # | 命中 | 修复 |
|---|---|---|
| HIT-1 | C2-G5 校验和闸落错分支(usage 254/255 密文分支)——所有已锁定私钥导入被拒(1/65536 才侥幸通过) | 闸移至 usage-0 明文分支;v4/v6 双形态容差保持;gpg 探针复验 |
| HIT-2 | OPS 配对状态不跨压缩层:Compressed(OPS)+外层签名逃逸配对校验;坏 OPS(不可解析)被静默吞掉、尾随签名照常验 Ok | ops+broken 穿层传递;坏 OPS → 全流 NotSigned(RFC 9580 §5.2.5) |
| HIT-3 | SHA-1/RIPEMD-160 签名 hashed 区无 creation-time 子包时 recent 闸从不触发(缺席=不可证明"不新") | 缺创建时间 → Failed(文档签名+密钥路径双处,§5.2.3.3 强制子包) |
| LAX-1 | Issuer Fingerprint 长度与八位组声明版本无联锁:33 字节体声明 v4(或 21 字节声明 v6)可过两道独立闸 | 联锁 fp_len:4→21、6→33,hashed+unhashed 双验证器同补 |

攻击面:X2 专门对准**修复边界本身**(新落闸门的错位、旁路组合、宽进残留),
四命中均为此类——单纯复测既有探针抓不到的回归类缺陷。

## 门禁

每轮提交前:三目标 native/wasm/js 全绿、fmt+deny-warn 过、ci_smoke PASS、
interop 45/45(夹具按 §12.4 重造后)、gpg 实机七向(acceptance 深验证含
2 GiB Argon2 慢向量)。

夹具重造说明(2026-11-20):C2-G4 闸落地后,三把 rsa1024 遗留夹具
(interop_our_key/interop_gpg_two_uid_key/key_expiredKey)在导入即被
MUST NOT 语义拒绝——按 RFC 9580 §12.4 原文("MUST NOT encrypt, sign, or
verify using RSA keys of a size less than 2048 bits")这些夹具本身已是非
符合性材料。重造:前两把换 rsa3072 走原 gpg 舞步(键仍由本库生成后导入
gpg 接受),key_expiredKey 以库内铸造复刻(generic 认证、flags 0x03、
creation 1、Signature Expiration 1337 s),派生向量(encrypted/sig/aes128/
pgp-mime/mime 三件)全部由 gpg 2.4.5 重新产出。
