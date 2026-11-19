# JEV 循环第 1 轮（2026-11-15 13:39 起）

目标流程：扫描 → 修复 → 验证 → 文档 → 提交，循环至「连续 2 轮无新 bug」或
2026-11-16 09:00。JEV 请求/响应存档 `/tmp/jev_goal_20261115/`。

## 扫描

三个 agent 分面（并发上限连续撞限，按 5 分钟退避串行重试后全部回报）：

- A：cipher/ + primitives/ + s2k/ + compress/ + error/（既往缺口分面）→ 2 条
- B：api/ + cmd/ + agent/ + 顶层 + example/netmail → 9 条
- C：pki/ + packet 写侧 + armor/ + interop/ + reference/ → 7 条（AR-1 与本轮
  自查 R1 重合，合并处置）

主循环自查（agent 分面之外）：mail/ + mime/ + example/mailreader + cmd/main → 2 条。
所有 17 条候选逐条 JEV noul 单题验证（一题一判，含 2 条复议：api3 0.884→0.990、
pk4 0.802→0.994），全部 ≥0.99 或经复议确认。

## 确认并修复（17 项）

| id | 缺陷 | JEV | 修复 |
|----|------|-----|------|
| M1 | mailreader `--resync` 布尔旗标吞下一参数（文档组合 `--resync --fetch 42` 报 unknown flag；`--resync --out` 静默丢 --out） | 0.998 | parse_args 布尔旗标特判 |
| Q1 | mail/build 7bit 分支不查行长（RFC 2045 §2.10 的 998 上限；严格 MTA 500/552） | 0.997 | is_ascii_text 加 MAX_7BIT_LINE |
| A1 | argon2 `8*parallelism` Int32 回绕绕过最小内存防护 → 零长 mem → SIGABRT（p≥2^28 探针实锤杀进程） | 0.996 | wire 对齐 cap：passes/parallelism ≤255（F3 先例） |
| A2 | argon2 passes 无上限 → 直构 2^30 挂死 | 0.960 | 同上（红态=数小时挂起，修后断言） |
| M2 | cmd basename 字符计数 vs UTF-16 切片漂移（F22 的 cmd 孪生实例） | 0.986 | code-unit 扫描（F22 模式） |
| M3 | parse_bits 乱码静默回退 3072（违反 m5 大声失败约定）+ generate_rsa_key 无上限 | 0.992 | parse_bits raise + RSA ≤16384（OpenSSH cap） |
| R1 | armor encode headers 无校验 → CR/LF 注入伪行（mail 侧 require_ascii 的 armor 孪生缺口） | 0.993 | require_armor_header；encode 签名改 raise（.mbti 变更） |
| pk1 | serialize_packet_old 已知 tag≥16 翻成新格式另一 tag（17→4，F8 的同算术残余） | 0.988 | 老格式 tag 域 4 bits 闸 |
| pk2 | extract_literal 逐包重序列化 → parse 接受的 Unknown(保留号) 包使整条解密硬失败（gpg 跳过继续） | 0.988 | 包列表直通重构 + Unknown 跳过（探针双红） |
| pk3 | PublicKeyPacket::parse 无尾随消费闸 → import 接受垃圾字节、to_body 丢字节、v4 指纹漂移 | 0.983 | r.remaining()==0 闸（F6 parity） |
| pk4 | v6 签名/OPS to_body 不复检 salt 尺寸/指纹宽度 → 直构面写的自家 parse 拒收 | 复议 0.994 | salt_size_of_hash 对照 + v6 指纹 32-octet 闸（SIG/OPS） |
| pk5 | literal 'l'（RFC 9580 LF-text）wire→wire 往返改写 0x6C→0x62（'t'→'u' 有登记，'l' 没有） | 0.994 | 'l' 注册为独立格式 + to_body 写回 0x6C |
| net1 | imap_fetch_recent last_n≤0 构造 FETCH 6:0 倒序非法段（docstring 声称的钳制不存在） | 0.959 | guard last_n≥1（探针桩驱动） |
| cmd1 | lock/unlock 原地截断重写唯一密钥文件，写中途失败=钥毁 | 0.983 | temp 文件 + rename(2) 原子替换（native），非 native 保持原样 |
| ct1 | cleartext 签名对尾空白行自产自不可验；gpg 实机锚定规范形语义（只排除最后一个行尾分隔符，其前尾空行是内容；显示层从原文构建） | 0.962 | canonicalize_cleartext 重写 + dash_escape_display 从原文构建 + 3 个 gpg 夹具回归（testdata/gpg-cleartext-*） |
| api1 | 五处重试循环把类型化错误压成字符串（j13 只修了 sign.mbt 一处） | 0.995 | Error? 重抛（builder×3、pubkey、sessionkey） |
| api2 | EncryptionBuilder::finish 静默丢弃 password（recipients 分支）与 signer（密码分支），违反 docstring 组合承诺 | 0.995 | seal_esks_and_seipd 统一封装（PKESK+v4 SKESK 共享会话钥）+ signed/literal_inner_stream + v6 inner 封装；v6 recipients × v4 口令显式拒 |
| api3 | recover_session_key_with_key 对损坏 RSA PKESK 把 S04 掩码随机钥当成功返回 | 复议 0.990 | unwrap_pkesk_checked（恢复路径诚实失败；解密路径保持掩码） |
| api4 | from_armored 只导入拼接钥环第一块（gpg --import 语义），其余静默丢失 | 0.986 | decode_all 扫描 + 多钥块显式拒（Message/Signature 垃圾块仍容忍） |
| api5 | v4 SKESK 读侧长度闸只认无校验和形状；恢复路径 1/256 错误口令假成功 | 0.968 | **改判**：RFC 9580 §5.3.1 已删除 v4 SKESK 的 2-octet 校验和（明文 esk = 算法字节 + 会话钥），原写侧形状才合规——首版「补写校验和」修复被 gpg 实机探针否决（weird size for an encrypted session key (35)，提交前功能复验拦下）后回滚；最终处置=写侧保持 9580 形状，读侧兼容 4880 时代带校验和形状（校验和即 unwrap 时证明，错误口令 WrongPassphrase 前移），恢复路径假成功为无校验和形状的格式固有 |
| api7 | verify_detached 只验第一个 Signature 包 → gpg 双 -u 分离签名对第二把钥必假阴性 | 0.979 | 遍历全部签名包，Ok 胜出否则取最差 rank |

（表中 17 条 = agent 15 条去重 AR-1 后 14 条 + 自查 2 条 + A 分面 2 条 - 重复合并；
API 编号沿用 agent 报告。）

## 不修/改判（本轮）

- pk4 首轮 0.802 复议后 0.994 修复（非不修）。
- api6 孤立代理对：纯 MoonBit 无法构造（lexer 拒绝 + Int::to_char 校验），
  防护落在 utf8_bytes chokepoint 服务 js 宿主边界（JS 字符串可携带）；
  修复可测面=合法增补平面往返，孤立代理分支无语言内可运行探针（记录）。
- A 分面否决清单：aead chunk_size 转换不可达、bzip2 BWT/Huffman 界受防、
  zlib NeedMoreOutput 不可达、Argon2 index_alpha 代数验证等（详见 agent 报告存档）。

## 测试与门禁

- 探针转正：cmd/main_wbtest（新建）、mail/build_test、primitives/argon2_test、
  packet/packet_test、api/pk2_wbtest（新建）、api/hackround2_wbtest（新建）、
  example/netmail/imap_wbtest、example/mailreader/main_wbtest、armor/armor_test、
  interop/gopenpgp_test（gpg 夹具）、pki/pki_test。
- 红态证据：M1（unknown flag '42'）、Q1、M2（/file.txt）、M3、A1（SIGABRT
  杀原语测试进程）、pk1/pk3/pk5、pk2（双红：serialize 拒 + leading Unknown）、
  pk4（stash 双探针红）、net1、ct1 夹具（Failed≠Ok ×2 + 首 fix 规则被 gpg
  夹具否定后重写）、R1（encode 收下 CR/LF）、api4（stash 轮:拼接钥环静默导入）。
- 修后断言（红态不可安全运行）：A2（挂死）、M3 上限（挂死）。
- 红态不可重建（如实记录）：api1/api2/api3/api7——这四项的修复与跨文件签名网
  （armor encode→raise、utf8_bytes→raise、unwrap 四元组、builder 统一封装）
  交织,孤离 stash 任一文件即编译失败,全量回退又与未跟踪探针所依赖的新 API
  冲突;其机制均经代码逐行核实 + JEV 0.98–0.995 + 修后行为测试锁定。教训:
  跨文件重构前应先落红探针（本轮 pk1/pk2/pk3/pk5/net1/ct1 等均按此序）。
- .mbti 变更（预期）：armor encode→raise、pk 的 ecdh_anonymous_sender→raise、
  api/revocation 内部函数；pkg.generated.mbti diff 在提交中逐条核对。

## 遗留

- 无本轮新登记；既往登记（A1 packet pub(all) 0.5.0+、#2/#3/#4）不变。

## 第 2 轮(同日,修复 diff 复审 + 遗留候选)

diff 复审 agent 通读 15807e5 全量 diff,5 项发现(F1 高/F2-F3 中/F4-F5 低),
另把第 1 轮登记的「密码路径不验内嵌签名」升级为候选(pw-verify,JEV 0.997)。
全部处置:

| id | 发现 | JEV | 处置 |
|----|------|-----|------|
| pw-verify | DecryptionBuilder 口令分支忽略 verification_key:内嵌签名的口令消息返回 Data(与密钥路径分叉,调用方不可区分「无签名」与「有签名未验证」) | 0.997 | decrypt_password_and_verify(新):open_password_container(容器解密出原始内层流)+collect_data_sig+逐验签者取最优 rank;builder 口令分支接线(红探针 NotSigned≠Ok→绿) |
| F1 | .password_v6().recipient() 组合仍静默丢 v6 口令(recipients 分支不消费 passwords_v6)——api2 同类残留 | 0.626→**探针实锤**(v6 口令持有者解不开,探针推翻低分) | 显式拒(fail-closed);RFC 允许 v6 SKESK+v6 PKESK 共存,真支持登记后续 |
| F2 | api3 探针假阳性:corrupt[14] 翻的是 MPI 位长低字节,F6 尾随闸在 unwrap 前就拒包,修复前后同绿 | — | 探针改 corrupt[16](MPI 值内);红态经外科式单行回退(unwrap_pkesk_checked→unwrap_pkesk)捕获:掩码路径返回垃圾钥假成功(`false` is not true),恢复 checked 后绿 |
| F3 | cmd1 原子替换权限回归:temp 文件继承 umask 0644,rename 换 inode 后用户收紧的 0600 丢失(私钥本地泄露面);写中途失败残留 temp | 0.990 | temp 文件 chmod 0600(唯一调用者是 lock/unlock 私钥)+errdefer 清理(写失败/rename 失败均无残留);实机验证 lock 后 stat=600 |
| F4 | ct1 docstring 写的规范形字节与实现矛盾("text\r\n\r\n" 应为 "text\r\n");往返测试注释承诺断言但代码 `let _ = returned` | — | 注释改正;补真断言 canonicalize(returned)==canonicalize(text) |
| F5 | verify_detached 多包遍历:结构损坏的后续包以 Malformed 压掉先前包的确定性失败结论 | 0.991 | 逐包 parse+verify 收敛为 Failed rank,不逃逸异常 |

diff 复审同时确认其余修复干净(会话钥长度三处对齐、esk 双形状无混淆、ct1
边界自洽、extract_literal 重构等价、argon2 caps 与 KAT 兼容、from_armored
诱饵无误伤、api7 best 语义正确等,清单见 agent 报告)。

教训:修复 diff 自身的复审价值再次印证(api2 的 v6 半边残留、cmd1 的权限面
回归都是修复引入/未闭合的新问题);探针判据要落到「能区分修复前后」的字节位
(F2 首版探针两个世界同绿,等于没测)。

## 第 3 轮(同日晚)

两部分扫描:复审 3166fc7 diff + 首次覆盖 example/mailer(本周期全部轮次未扫的
示例);另发现 interop_check.sh 的 CLI 调用仍是 D1 改造前的位置口令签名
(方向 5/7 假失败)。JEV 6/6 确认(0.92-0.996),全部处置:

| id | 发现 | JEV | 处置 |
|----|------|-----|------|
| PV-1 | **第 2 轮 pw-verify 引入回归**:decrypt_password_and_verify 把 unwrap_skesk 放在重试循环外——v4 免校验形状 1/256 错口令假 unwrap 后,容器失败炸掉整个调用,正确的 SKESK #2 永不尝试,错误类从 WrongPassphrase 漂移为 Malformed;S2KBudget 作用域也被稀释 | 0.959 | 验证并入 decrypt_binary_with_password 的 SKESK 循环(verify~ 参数):N4 重试/共享预算/E7 分类全恢复;decrypt_password_and_verify 变薄封装;确定性回归测试(SKESK#1 包错钥+#2 包真钥,旧路径必炸) |
| PV-2 | mailer parse_args:-- 前缀值可作前一旗标的值(--subject --roundtrip 静默禁用离线回环走真实发送;--smtp-user --smtp-pass-env 两组凭据同丢);布尔旗标 --roundtrip 在无特判取值路径 | 0.924 | 布尔旗标特判 + 值拒 -- 前缀(M1 类) |
| PV-3 | mailer --smtp-port 手写累加器:空串→端口 0,10 位数字 Int32 回绕 | 0.985 | parse_int + 1..65535 严格界 |
| PV-4 | mailer file 模式只拒 --smtp-tls/--smtp-trust(2026-10-06 review 关了一半),其余四个 smtp 旗标仍静默忽略 | 0.995 | guard 扩展到全部四个 |
| PV-5 | mailer on_attachment 把整个 Content-Disposition 头值当附件名(filename= 提取是空操作) | 0.996 | 解析 filename token(含引号/分号处理);实机 roundtrip 验证 attachment: report.pdf |
| PV-6 | cmd1 原子替换残留:create(umask 0644)→写私钥→chmod 0600 之间存在可读窗口 | 0.996 | 先建空文件→chmod 0600→再写内容(截断自有 0600 文件保 mode) |
| 脚本 | interop_check.sh 方向 5/7 的 CLI 调用仍是位置口令(D1 前签名) | — | 改 --pass-env NAME;七方向全 PASS |

diff 复审同时确认 R2 六项修复本体大多成立(builder 状态映射与密钥路径一致、
verify_detached 逐包 catch 两形态 fail-closed、chmod 类型正确等)。
教训:新写路径(第 2 轮 pw-verify)必须对照既有循环的语义清单(重试/预算/
错误分类)逐项核对——PV-1 三项全丢正是漏了这张清单;修脚本陈旧调用属于
「门禁自身也是被审计对象」的范畴。

## 第 4 轮(同日,复审 65ba0c6)

复审 agent 核验 R3 六项修复本体全部成立(verify~ 重构与空分支等价、解压预算与
S2KBudget 不相交无重复记账、to_lower 索引对齐、PV-6 两阶段写 POSIX mode 语义、
F1 guard 覆盖完整、pv1 测试具回归检出力)。发现 1 低危缺陷+2 备注:

| id | 发现 | 处置 |
|----|------|------|
| r4f1 | mailer on_attachment 引号内分号截断文件名(filename="a;b.pdf"→"a"):引号值应扫描至闭引号 | 已修(引号值扫描闭引号,裸值扫描分号);探针形状 agent 已预跑 |
| 备注1 | PV-2 的 -- 前缀拒绝使 -- 开头值不可表达(纯可用性收窄,fail-loud 无静默危害;无 --flag=value 与裸 -- 终止符) | 登记,不改 |
| 备注2 | 「多 SKESK 重试 × verifiers 非空」组合无测试 | 补 pv1b 测试(错误钥 SKESK#1+真钥 #2+验签者非空→NotSigned,旧 standalone 路径必炸) |

门禁:native 639/wasm 630/js 630(数字随测试增长)、smoke PASS。

## 第 5 轮(2026-11-17 凌晨,复审 ac1974b——跨零点续跑)

R5 复审 agent 因配额中断,遗留线索已核实:mailreader on_attachment 的分号分割
不识别引号,与 mailer r4f1 同形(处理不可信网络输入)。

| id | 发现 | JEV | 处置 |
|----|------|-----|------|
| r5-mr | mailreader 附件名提取:filename="a;b.pdf" 截断为 "a"(探针红收据:inspect actual="a");防穿越闸不受影响,影响=攻击者可控截断 | **通道中断**:MAGPIE 关停致 401(重试 3 次+预热重试均 401),按探针裁决推进;恢复后可补验 | 引号值扫至闭引号、裸值扫分号(mailer r4f1 同款);探针转正为三断言回归(引号全名/裸值分号/穿越闸) |

R5 其余复审范围:pv1b 已在第 4 轮门禁实跑通过(639/639 含该测试);mailer
引号扫描边界已由第 4 轮 agent 预验证;F2 备注决定(不改)复核维持。

## JEV 通道状态(2026-11-17)

第 5 轮起 MAGPIE 关停导致直连 401;用户重启 MAGPIE(localhost:11434)后,其
tokenrhythm-cn 组仅服务 chat,/v1/decisions 与 /v1/systemone 被拒
("only an OpenAI API key, Azure OpenAI and another magpie serve it"——重启后
的 magpie 未接决策模型上游),直连 tokenrhythm.studio 仍 401。第 5 轮候选
(r5-mr)先按探针收据裁决;用户重启 MAGPIE 并给出模型 id(jev/NeoHorse-Jev-4B)
后,经 MAGPIE 补跑正式验证 **p=0.996**(与探针一致)。MAGPIE 形态与直连不同:
POST localhost:11434/v1/decisions,体={model:"jev/NeoHorse-Jev-4B", input:<state>,
questions:[{type:"predicate|choice|score", instructions}]},响应 answers 为数组
(与 questions 顺序对应,probability 字段);noul 在此路由叫 predicate。

## 第 7 轮(2026-11-17 凌晨,脚本扫+acceptance 深验证)

脚本面扫干净(e2e* 全部 --pass-env 或未锁钥,ci_smoke 的 decpriv 走未锁钥无需
口令);acceptance.sh 深验证(含本周期从未实跑的 #skip 慢向量)抓到 1 项:

| id | 发现 | 处置 |
|----|------|------|
| r7-slow | 慢向量测试「A.5 v6 unlock 错口令」的 catch 仍期望泛型 PgpError 变体——10-27 类型化轮(ed68c4c)把 lock.mbt AEAD 路径改为 WrongPassphrase 后慢套件无人跑,期望漂移 | pre-cycle HEAD(1172424)worktree 实证同位同失败=既有问题非本轮回归;catch 改接受类型化 WrongPassphrase,慢向量 2/2 绿 |

教训:#skip 的慢测试不在常规门禁里,期望漂移可潜伏数周——acceptance 深验证
应周期性实跑(本轮 R7 即靠它抓到)。

R7 扫描其余部分干净:e2e*/acceptance 脚本无陈旧调用残留(R3 同类问题的
残余面核查),acceptance 的 1-3/5 步全绿(640/631)。

## 第 9-10 轮(2026-11-17 清晨)

第 8 轮复审 0028f84 判定干净(unlock 全分支 raise 面闭合、消息文本匹配、
无断言交互——干净轮);第 9 轮终局扫描(净 diff 交互+文档一致性+测试同步)
抓到 4 项(1 行为级+3 文档级),全部处置:

| id | 发现 | JEV/裁决 | 处置 |
|----|------|-----|------|
| r9-1 | password+verifiers 内联验签块无 per-verifier catch:未知 hash_algo 的签名抛 Unsupported 会作废已解密数据、阻止其余验签者(与 verify_detached 的 api7 约定、密钥路径逐对 catch 均分叉;wire 可达:parse 不校验 hash_algo 字节) | R9 agent 代码链路核实(sign.mbt:30 经 finish_signed_digest 先于优雅 Failed 分支) | per-verifier try/catch→Failed(api7 约定对齐),数据保留、其余验签者继续 |
| r9-2 | RSA 16384 上限(M3)零文档声明:CHANGELOG 无 Breaking 条目、README 中英只有 3072 下限 | — | CHANGELOG Breaking 条目+README 中英补上限 |
| r9-3 | decrypt_binary_with_password 签名破坏性变更(Bytes→(Bytes, VerifyStatus)+verifiers?)与 ecdh_anonymous_sender→raise 未入 CHANGELOG | — | 补 Breaking 条目 |
| r9-4 | hackround2 api2 测试注释仍是「password 路径不验内嵌签名——登记遗留」,与 round-3 修复矛盾,会误导后续轮次 | — | 注释更新为已闭合 |

## 第 11-12 轮(2026-11-17 清晨,复审 c718981)

第 11 轮复审判定 r9-1 核心语义正确(Unsupported raise 面核实、catch-all 不吞
E7/N4 错误、best-rank 与 verify_detached 逐句同构、文档三类与代码一致),
2 条低危,第 12 轮处置:

| id | 发现 | 处置 |
|----|------|------|
| r11-1 | 「对齐」表述过强:未知 hash_algo 的 verifier 在 password 路径现为 (d, Failed)(数据保留),密钥路径仍 raise(数据丢失)——两条解密路径新不对称,未登记 | plan/CHANGELOG 登记该已知不对称;**归一化落点=finish_inline_verify(sign.mbt:394,无 catch)与 cleartext.mbt 裸调用,非 builder 的 last_error 环节**(r13 勘误) |
| r11-2 | r9-1 零回归覆盖:全仓无未知 hash_algo 签名构造,若 catch 被「简化」掉门禁仍全绿 | 补 r9-1 回归测试(手工构造 hash_algo=0x63 的签名+verifier→(payload, Failed),数据保留) |

## 第 16 轮与收尾(2026-11-17 早晨)

第 16 轮终局复核抓到 **f16-1(低中危,R3 引入回归)**:PV-4 的 file-mode guard
比较 `smtp_host == "localhost"`,而 Config 默认值是 "127.0.0.1"——默认 file
投递(用户零旗标)必然误报失败,与 pv4 注释意图(对用户实际设置的旗标大声
失败)相反。历轮漏网原因:mailer 是 example 包零测试覆盖,e2e 两用例恰好绕开
guard(smtp 显式传参/roundtrip 提前返回)——即 r11-2 登记过的「零覆盖场景」
同型。pre-probe 实锤(默认流程报 guard 错误)。

处置:guard 对齐默认值(127.0.0.1:2525);实机双向验证——默认投递恢复
(f16.eml 落盘)、显式非默认 smtp 旗标仍大声失败。第 16 轮其余三项交叉验证
干净(提交间无「后轮撤销前轮」、工作区干净、CHANGELOG 对账完整、三处 usage
与 README 一致、openwiki/api.md 与代码现状一致)。

## 收尾轮(2026-11-18,worktree followup-20261118)

用户令:创建 worktree 解决剩余未处理项。worktree /Users/john/Downloads/moonpgp-followup
(分支 followup-20261118 @5338f92),两项登记后续落地,合并回 main(快进 3ed41dd):

| 项 | 内容 | 回归测试 |
|----|------|-----|
| ① v6 组合(第 2 轮 f1 登记) | `.password_v6().recipient()` 真支持:`build_v6_skesk` 从 seal_skesks_v6_inner 抽出复用,seal_esks_and_seipd 增 passwords_v6 参数(v6 SKESK 与 v6 PKESK 共享会话钥、同前置 v2 SEIPD,RFC §10.3.2.1);v4 收件人×v6 口令、entry AEAD 与收件人套件不匹配仍大声拒 | v6 组合双路径可解密 + v4×v6 大声拒(stash 红收据:F1 拒绝句/静默丢) |
| ② 密钥路径归一化(第 11 轮 r11-1 登记,r13 勘误定位) | finish_inline_verify 与 cleartext verify_cleartext 的裸 verify_signature_packet 加 per-verifier catch→Failed——未知 hash_algo 签名在两条解密路径均为 (数据, Failed);verify_cleartext 同享 | key-path 容错测试(手工 hash_algo=0x63 内嵌签名,stash 红收据:Unsupported 逃逸) |

门禁(worktree 与 main 各一遍):native 643/643、wasm 634/634、js 634/634、
fmt+deny-warn 过、ci_smoke PASS。worktree 已移除、分支已删。

剩余未处理项终态:①② 已解决;PV-2 可用性收窄维持「登记不改」(fail-loud 无
静默危害);JEV 直连 401 为用户侧事项(MAGPIE 形态已入方案与记忆)。

## 符合性+攻击轮(2026-11-19/20,worktree audit-20261119)

用户令:创建 Worktree,一边检查项目是否符合 PGP 的所有要求,一边像安全
团队一样审查代码漏洞、不断发起攻击测试。worktree audit-20261119(分支
audit-conformance-20261119 @3ed41dd),两轮符合性 agent(C1 包格式 33 条款
簇 / C2 密钥材料约 50 条款簇)+两轮攻击 agent(X1 预认证面中断/X2 攻修复
边界终局),合并回 main(快进 e504b4f):

- **17 项 MUST 级 GAP 全修**(C1-G1..G7 / C2-G1..G7,全表见
  report-conformance-20261119.md):§4.3 未知关键包闸、SKESK 零 IV 随块长、
  Ed25519 摘要≥256、issuer-fp 版本交叉+长度联锁、Marker 跳过、OPS↔签名
  Table 27 配对+nested 位、v6 弱哈希双闸、生成侧拒签、收件人偏好算法选择、
  RSA ≥2048 三入口、usage-0 校验和、p<q 归一化、SHA-1/RIPEMD-160 recent
  截止。
- **攻击轮命中 4 项全修**(X2 专攻修复边界自身):HIT-1 校验和闸落错分支
  (锁键导入全断)、HIT-2 OPS 配对不跨压缩层+坏 OPS 静默吞、HIT-3 缺创建
  时间旁路 recent 闸、LAX-1 issuer-fp 版本-长度联锁缺失;探针翻转回归。
- SHOULD 级文档化偏差 8 条登记(C1-G8/G9/G10 等,随 0.5.0 决策)。
- 夹具重造:rsa1024 遗留三把按 §12.4 重造 rsa3072(key_expiredKey 库内
  铸造复刻),派生向量 gpg 重出,interop 45/45。
- 门禁:native 684/wasm 675/js 675 全绿、deny-warn 过、ci_smoke PASS、
  gpg 实机七向 PASS。worktree 已移除、分支已删。

### JEV 审查轮(2026-11-20,对 e504b4f)

按 jev-code-review 技能+项目纪律(MAGPIE 通道、一题一请求、逐字代码 state、
场景化单正向陈述、阈值 0.9)对六个语义修复面发七题,全过无需探针复核:

| # | 审查面 | 概率 |
|---|--------|------|
| q1 | HIT-3 缺创建时间→Failed(双路径同构) | 0.9971 |
| q2 | 坏 OPS→整流 NotSigned(数据仍交付) | 0.9943 |
| q3 | OPS 状态穿层配对不误拒合法流 | 0.9643 |
| q4 | usage-0 校验和闸位置与豁免(v4 带/v6 免) | 0.9961 |
| q5 | issuer-fp 版本-长度联锁唯一合法形状 | 0.9815 |
| q6 | 偏好选择三段语义(交集/回退/fail-loud) | 0.9716 |
| q7 | §4.3 criticality 闸+Padding 21 建模 | 0.9748 |

覆盖面声明:JEV 仅裁决六个语义修复点;夹具重造(机械性)、gpg 实机七向、
三目标测试不在 JEV 覆盖内(已有实收据)。

## 推送+0.5.0 规划轮(2026-11-20)

用户令"完成这两步"(推送+范围规划):

- **步①推送**:1172424..8015212 推上 GitHub(此前远端 main 停在 11-13,
  schedule interop 连红即旧脚本+新 CLI 错配所致,推送即愈)。推送触发 CI
  check 挂于工具链漂移:CI 每次装最新 moon,已弃用 Bytes::new/
  Buffer(size_hint=)/Int64::from_int/BigInt::from_string,--deny-warn 下成
  错。本地升 moon 0.1.20261117 对齐后机械迁移 156 处(141+12+2+5)+发现
  --target all 下 cstring 未用→#cfg native 域+手写标量编码(去 primitives
  依赖)。3a3ae39+a41f009 推送,check/build/smoke 全绿,三目标测试跑中。
  教训:本地工具链必须跟 CI 同步升级,门禁口径 moon check --target all
  --deny-warn(非默认 target)。
- **步②0.5.0 范围**:RFC 原文核实(§5.2.3.35 issuer-fp SHOULD all signatures;
  §5.2.3.11/.29 双 SHOULD critical;§9.5 SHOULD NOT SHA-1 依赖;§12.4 字面)
  +JEV 九题逐项 predicate。纳入 5 项(S1 issuer-fp 0.9978/S2 critical 位
  0.9832/S3 直构域 0.9963/S7 压缩偏好 0.9526/S8a lock v6 拒绝 0.9416),
  维持登记 4 项(S4 v6 默认/S5 Ed448/X448/S6 RSA 2048 线/S9 SED,均≥0.98)。
  s8 首判 0.7052 触发复议纪律,拆三方案 0.9416/0.3731/0.2854 定案。
  文档:plan-0.5.0-scope-2026-11-20.md。
