# Qualia2FA-FFI

把 [`qualia2fa-core`](https://github.com/QiuShui1012/Qualia2FA-Core) 暴露为
[UniFFI](https://mozilla.github.io/uniffi-rs/) 绑定，供 Kotlin、Swift 等托管语言调用。

| 项 | 值 |
|---|---|
| Crate 名 | `qualia2fa-ffi` |
| 类型 | `cdylib` + `staticlib`（另有 `uniffi-bindgen` 二进制） |
| Edition | 2024 |
| 许可证 | `LGPL-3.0-or-later` |
| UniFFI | **`0.29`** |

已导出 OTP 相关能力；保险库与同步待后续实现。

## 用法

### 1. 构建动态库

```bash
cargo build --release
```

产物为 `target/release/qualia2fa_ffi.dll`（Windows）、`.so`（Linux/Android）、
`.dylib`（macOS/iOS）。要静态库则取同目录下的 `.lib`/`.a`。

### 2. 生成端侧绑定

绑定生成器是本仓库自己的二进制，这样**生成绑定所用的 UniFFI 版本与库编译时
所用的完全一致**。改用全局安装的 `uniffi-bindgen` 会让两边版本漂移，产出
「能编译但运行时不匹配」的绑定。

```bash
cd FFI    # 必须在仓库根执行：uniffi-bindgen 内部会调用 cargo metadata

# Kotlin（JVM 桌面端与 Android 共用同一份绑定）
cargo run --bin uniffi-bindgen -- generate \
    --library target/debug/qualia2fa_ffi.dll \
    --language kotlin --out-dir ./bindings

# Swift（iOS）
cargo run --bin uniffi-bindgen -- generate \
    --library target/debug/qualia2fa_ffi.dll \
    --language swift --out-dir ./bindings-swift
```

生成的绑定落在 `bindings/`、`bindings-swift/`，**不入库**——它们是派生物，应由
端侧构建流程在编译前生成。入库会立刻产生「绑定与接口定义不同步」的问题：改了
Rust 签名却忘了重新生成，编译期不报错、运行期才崩。

> 提示若出现 `Unable to auto-format ... using ktlint: program not found`，只是缺少
> 可选的 `ktlint`，产物依然正确可用。

### 3. 在 Kotlin 中调用

生成的绑定位于 `uniffi.qualia2fa_ffi` 包下，函数为顶层函数：

```kotlin
import uniffi.qualia2fa_ffi.*

val entry = parseOtpauthUri("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP")
val code = totpCode(entry.secretBase32, System.currentTimeMillis() / 1000, entry.period, entry.algorithm, entry.digits)
```

### 4. 分发动态库

绑定通过 JNA（JVM）或系统动态加载器（Swift）按**名字**查找动态库，因此
`qualia2fa_ffi.dll` / `libqualia2fa_ffi.so` / `libqualia2fa_ffi.dylib` 必须与
应用一起分发，并落在加载器能找到的位置。各平台的放置方式由端侧构建决定。

## 接口

### 验证码

| 函数 | 说明 |
|---|---|
| `parse_otpauth_uri` | 解析 `otpauth://` URI |
| `serialize_otpauth_uri` | 序列化回 URI（账号名含 `:` 会被拒绝） |
| `totp_code` / `hotp_code` | 计算验证码 |
| `steam_guard_code` | Steam Guard 5 位字母表 |
| `verify_code_with_drift` | 容错校验，返回命中的偏移量便于时钟校准 |
| `codes_match` | 常量时间比较 |
| `generate_secret_base32` | 生成 256 位随机种子（OS CSPRNG） |
| `recommended_min_secret_len` / `is_secret_shorter_than_recommended` / `secret_byte_len` | 种子强度提示 |
| `core_version` | 核心版本，供兼容性检查 |

**时间一律由调用方传入。** 核心不读时钟，只有时间作为参数传入，RFC 6238 的
测试向量才能被确定性地验证。端侧应传系统时钟的 Unix 秒数。

### 保险库（`FfiVault`）

条目本身由 `FfiVault` 持有，**主密钥留在 Rust 侧**。「打开 → 列条目 → 改条目 →
存回文件」这条最常见的路径上，主密钥一次都不会以字节形式出现在 Kotlin/Swift 里。

| 方法 | 说明 |
|---|---|
| `FfiVault.register(keys, store, label)` | 生成主密钥、取得设备身份、写入平台密钥库 |
| `FfiVault.open(store, data)` | 用密钥库里的主密钥打开保险库文件 |
| `FfiVault.fromMasterKey(bytes)` | 用已有主密钥建立空保险库（登录/恢复之后用） |
| `entryCount` / `isEmpty` / `tombstoneCount` | 计数 |
| `entries` / `entry(id)` | 读取条目（**顺序不保证**，列表请自行排序） |
| `addEntry(entry, now)` → `id` | 新增 |
| `updateEntry(entry, now)` | 修改（**标识不变、不留墓碑**） |
| `removeEntry(id, now)` → `Bool` | 删除（留墓碑） |
| `serialize` | 序列化，供端侧**原子地**落盘 |
| `totpFor` / `hotpFor` / `steamGuardFor` | 直接按条目算验证码 |
| `exportRecoveryKey(passphrase, …)` | 导出恢复密钥文件 |

`updateEntry` 与 `removeEntry` 的区别不只是语义：修改保留条目标识，删除留下墓碑。
两者在另一台设备上被读成完全不同的操作，因此**不要**用「删除 + 新增」实现修改。

### 注册与登录

```kotlin
// 新设备注册
val vault = FfiVault.register(deviceKeys, secureStore, "qualia2fa-device")

// 老设备（已登录）：出示二维码
val login = FfiLogin.begin()
showQrCode(login.payload())

// 新设备：扫码、发请求、拿回应答后完成
val joiner = FfiJoiner.fromQr(scannedText, "qualia2fa-device")
val request = joiner.request(deviceKeys)
// …把 request 交给老设备…
val reply = login.authorize(oldVault, request)   // 界面在这里必须先让用户确认
val masterKey = joiner.complete(reply, deviceKeys, secureStore)
```

| 方法 | 说明 |
|---|---|
| `FfiLogin.begin()` / `payload()` | 发起登录，取得二维码文本 |
| `FfiLogin.authorize(vault, msg1)` | 授权（**调用即交出主密钥**，界面须先确认） |
| `FfiLogin.joinerDeviceId()` | 请求方的设备标识，显示给用户核对 |
| `FfiJoiner.fromQr(text, label)` | 扫码建立会话 |
| `FfiJoiner.request(keys)` | 发出请求（幂等） |
| `FfiJoiner.identity()` | 本机身份，完成之前才有值 |
| `FfiJoiner.complete(msg2, keys, store)` | 验证应答、取回主密钥、写入密钥库 |

一次登录只能完成一次。第二次调用报的是**与「应答是伪造的」相同的错误**，这是故意
的——单独报「已经用过了」等于告诉重放者他被认出来了。端侧文案也应保持笼统。

### 恢复密钥

| 函数 | 说明 |
|---|---|
| `FfiVault.exportRecoveryKey` | 设备已解锁时导出（主密钥不过边界） |
| `exportRecoveryKeyFromMaster` | 只有主密钥字节时导出 |
| `importRecoveryKey(file, passphrase, store)` | 导入并写入密钥库，返回主密钥 |
| `storeMasterKey(bytes, store)` | 单独保存主密钥 |

KDF 参数（`memory_kib` / `iterations` / `parallelism`）传 `null` 用推荐值
（64 MiB / 3 次 / 1 路）。**不要为了「快」调低**：导出是一次性开销，而拿到文件的
攻击者是离线暴力破解，参数调低直接削弱用户最后一道防线。

### 挑战-应答

用来证明「对方持有主密钥」而不把主密钥交出去。它与登录不同：登录传输密钥，它只做
证明。**三步都要走完**，漏掉第三步等于只做了一半认证。

```kotlin
val verifier = FfiVerifier.begin()
val responder = FfiResponder.accept(verifier.challenge())
val response = responder.respond(vault, label, deviceKeys)
verifier.verify(response, vault)                  // 第二步：主密钥确实对得上
responder.confirm(vault, verifier.sessionId()!!, verifier.confirmation()!!)  // 第三步
```

> **空保险库也能判定主密钥对错。** 文件格式版本 2 在末尾放了一个主密钥检查值，
> 因此 `FfiVault.open` 在**一个条目都没有**的文件上也会拒绝错误的主密钥。端侧可以
> 把「打开成功」直接当成「已解锁」。
>
> 例外是**版本 1 的旧文件**：那份文件里确实没有可判定的信息，需要权威确认时用
> 挑战-应答。

## 错误处理

FFI 错误跨到 Kotlin 后是 `sealed class FfiException`：

| 变体 | 含义 |
|---|---|
| `InputTooLong` | 输入超过边界上限 |
| `Core` | 核心返回的错误，结构化为 `FfiCoreError { kind, message }` |

`kind` 是**稳定的机器可读标识**（如 `secret_empty`、`vault_entry_not_found`），
端侧据此分流 UI；`message` 仅供展示与日志。这些字符串属于公开接口：**可以新增，
但既有值不得改名**。

有几组 `kind` 是刻意分开的，合并它们会造成用户可见的错误：

| kind | 不要与它合并 | 合并的后果 |
|---|---|---|
| `device_not_registered` | `vault_decryption_failed` | 用户被引导重新注册，原有条目永久丢失 |
| `vault_entry_not_found` | 「保险库为空」 | 显示空列表，而用户刚才还在看条目 |
| `recovery_authentication_failed` | `recovery_file_malformed` | 用户反复试口令，而问题不在口令 |
| `pairing_authentication_failed` | 任何更具体的错误 | 给攻击者一个「差一点就成功」的预言机 |

`pairing_authentication_failed` 覆盖密文被改、会话对不上、应答来自另一次登录等
多种成因，**这是刻意的**。端侧文案应当保持笼统（「配对失败，请重新扫码」），不要
试图从它推断更具体的原因。

核心是 `#[non_exhaustive]` 的，未来会新增错误变体，因此端侧**必须对未知
`kind` 有兜底分支**：

```kotlin
try {
    parseOtpauthUri(input)
} catch (e: FfiException.Core) {
    when (e.detail.kind) {
        "uri_missing_secret" -> showReenterHint()
        "randomness_unavailable" -> showRetryHint()
        else -> showGenericError(e.detail.message)   // 必须保留兜底分支
    }
}
```

## 秘密材料

跨 FFI 边界时，OTP 种子统一以 **Base32 字符串**表示（传入走 `from_base32`，
传出走 `to_base32`）。种子的字节**永远不会**以 `Vec<u8>` 形式经过 FFI——那会在
两侧各留一份不受擦除控制的拷贝。

> ⚠️ **端侧必须知晓的残留风险**：Base32 字符串在 Kotlin/Swift 侧是普通 `String`，
> 不受核心 `secrecy` 的擦除保护，且可能被 GC 复制、进字符串常量池。这是托管语言
> 的固有限制。端侧应约定：种子的 Base32 只在必要作用域内存在，用完立即丢弃，
> **绝不写入日志或持久化**。

**主密钥**同理但更进一步：它正常路径下**根本不过边界**。`FfiVault` 在 Rust 侧持有
它，读条目、改条目、算验证码、序列化都在 Rust 内完成。只有两个构造入口需要端侧交出
或接收它：

- `FfiVault.fromMasterKey(bytes)` / `storeMasterKey(bytes, store)`：登录或恢复之后，
  端侧手里已经有主密钥字节。
- `FfiJoiner.complete(...)` / `importRecoveryKey(...)`：返回主密钥字节，供端侧立刻
  建一个 `FfiVault` 或交给密钥库。

拿到之后端侧应当**立刻丢掉**那些字节。`FfiDeviceKeys` / `FfiSecureStore` 两个回调
之所以用字节而不是结构体，正是因为主密钥的永久归宿是平台密钥库，而只有端侧能访问
它——把整个密钥库抽象搬进 Rust 会让每个平台的 `unsafe` 跟着进来。

## 参与贡献

### 最重要的约定：这里只做搬运

本 crate 的职责是：把端侧传来的原始类型转成核心类型、调用核心、把结果转回去。

**任何加密、解析、校验逻辑出现在这里都是设计倒退。** 那些必须留在
`qualia2fa-core` 内，因为只有核心是无 `unsafe`、可独立审计的。代码审查时的
检查项就一条：**有没有把核心的逻辑搬到这里来**。

### 为什么这里不能 `#![forbid(unsafe_code)]`

`uniffi::setup_scaffolding!()` 在本 crate 内展开 FFI 边界所需的 unsafe 代码
（裸指针解引用、`catch_unwind`、字符串所有权转移）。**FFI 边界本身就是 unsafe
的**，这是不可协商的。安全边界因此划在 **crate 之间**：

| crate | 约束 |
|---|---|
| `qualia2fa-core` | `#![forbid(unsafe_code)]`，无 I/O，无时钟 |
| `qualia2fa-ffi` | 唯一允许 `unsafe` 的地方，且必须是薄的 |

`Cargo.toml` 里把 `unsafe_code` 设为 `warn` 而非 `allow`，是为了让任何**新增**的
`unsafe` 在构建时发出声音；CI 用 `-D warnings` 把它上升为硬错误。

### UniFFI 版本为何停在 `0.29`

上游最新是 `0.32.2`，但端的绑定生成器 **Gobley 强制 `uniffi = "0.29.4"`**，Rust
侧与 Kotlin 侧的脚手架**必须同版本**，否则生成的序列化格式不匹配。

取 `0.29`（等价 `^0.29`）而非写死 `=0.29.4`：`0.29.5` 已发布且同 minor 内 semver
兼容，既能吃到补丁又不会跨到 `0.30`。

这也是 **`uniffi` 不进 `qualia2fa-core`** 的原因：绑定生成器的版本锁定不该牵连
核心。核心保持与任何绑定工具无关。

### 提交前

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

本仓库 `path` 依赖 `../Core`（即 `qualia2fa-core`）。本地开发时该目录需存在；
CI 中以显式检出的兄弟目录满足（见 `.github/workflows/ci.yml`）。

## 许可证

LGPL-3.0-or-later，见 [`LICENSE`](LICENSE) 与 [`COPYING.LESSER`](COPYING.LESSER)。
