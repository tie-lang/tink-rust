# tink-rust

tink data-flow node frame protocol — Rust crate. Universal and language-agnostic:
any component that obeys the frame protocol can join a tink pipeline.

```
帧 = [ len: u32 BE ][ payload: len 字节 ][ crc: u32 BE ]
len = payload 字节数
crc = CRC32-IEEE(payload)（多项式 0xEDB88320）
```

Mirrors `std/tink.tie` (tie standard library) and the C / Python tink libraries;
pure functions over byte slices, IO (stdin/stdout) left to the caller.

## API

| function | description |
| --- | --- |
| `crc32(data: &[u8]) -> u32` | CRC32-IEEE over a byte slice. Check vector: `crc32(b"123456789") == 0xCBF43926` |
| `frame_encode(payload: &[u8]) -> Vec<u8>` | encode a payload into a full frame `[len][payload][crc]` |
| `frame_next(bytes: &[u8], pos: usize) -> Option<(Vec<u8>, usize)>` | parse one frame at `pos`, verify CRC; `None` on out-of-bounds / mismatch |
| `frame_skip(bytes: &[u8], pos: usize) -> Option<usize>` | skip one frame at `pos` without copying or verifying (zero-copy) |

## Usage

```toml
[dependencies]
tink = "0.1"
```

```rust
let f = tink::frame_encode(b"hi");
let (payload, next) = tink::frame_next(&f, 0).unwrap();
assert_eq!(payload, b"hi");
assert_eq!(next, f.len());
```

## Test

```bash
cargo test
```

## Cross-language

tink 帧协议各语言实现（API 语义与校验向量一致）：

| language | library |
| --- | --- |
| tie | `std/tink.tie` |
| Rust | this crate（`tink-rust`） |
| C | `tink-c`（`tink.h` + `tink.c`） |
| Python | `tink-python`（`tink.py`） |

## License

本仓库使用 **Tie Public License v2.0 (TPL 2.0)**，完整文本见 [LICENSE](LICENSE)。
This repository is distributed under the **Tie Public License v2.0 (TPL 2.0)** — see [LICENSE](LICENSE) for the full text.
