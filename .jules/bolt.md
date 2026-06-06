## 2024-06-06 - [Avoid format! for stringing integers in no_std]
**Learning:** In #![no_std] environments, avoid using `alloc::format!` for string construction inside hot loops to prevent intermediate allocation overhead. For formatting single integers, prefer `.to_string()` as it leverages the highly optimized `itoa` crate under the hood and allocates exact lengths.
**Action:** Use `.to_string()` instead of `format!` for simple integers.
