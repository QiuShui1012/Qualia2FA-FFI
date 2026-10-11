//! `uniffi-bindgen`：为端侧生成 Kotlin / Swift / Python 绑定。
//!
//! 这是 UniFFI 的官方集成方式——把绑定生成器做成库自己的二进制，从而保证
//! **生成绑定所用的 UniFFI 版本与库编译时所用的完全一致**。若改用全局安装的
//! `uniffi-bindgen`，两边版本漂移会让生成出「能编译但运行时不匹配」的绑定。
//!
//! 用法（在 FFI/ 目录下）：
//!
//! ```text
//! # Kotlin（JVM 桌面端 / Android 共用同一份绑定）
//! cargo run --bin uniffi-bindgen -- generate \
//!     --library target/debug/qualia2fa_ffi.dll \
//!     --language kotlin --out-dir ../UI/bindings
//!
//! # Swift（iOS）
//! cargo run --bin uniffi-bindgen -- generate \
//!     --library target/debug/qualia2fa_ffi.dll \
//!     --language swift --out-dir ../UI/bindings-swift
//! ```
//!
//! Windows 上动态库是 `.dll`；Linux 是 `.so`；macOS 是 `.dylib`。
//! 也可以先构建为 `staticlib` 再指向 `.a`/`.lib`。
//!
//! ⚠️ **生成的绑定不要手工修改，也不应提交进本仓库**——它们属于端侧产物，
//! 应由端侧的构建流程在编译前生成，放进本仓库会立刻产生「绑定与接口定义
//! 不同步」的问题。见 README 的说明。

fn main() {
    uniffi::uniffi_bindgen_main();
}
