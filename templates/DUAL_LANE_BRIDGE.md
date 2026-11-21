# Dual-Lane Coordination Bridge (`LANE 1` <-> `LANE 2`)

> Copy file này vào dự án của bạn (ví dụ: `artifacts/dual-lane/DUAL_LANE_BRIDGE.md`) và điền các thư mục sở hữu tương ứng với dự án của bạn để 2 luồng Codex chạy song song mà không bao giờ đụng file của nhau.

## 1. Phân vùng quyền sở hữu (Zero-Collision Ownership)

| Hạng mục | **LUỒNG 1 (`LANE_1` — Desktop App / `codex-t3`)** | **LUỒNG 2 (`LANE_2` — CLI Chính chủ `codex`)** |
| :--- | :--- | :--- |
| **Nhiệm vụ chính** | *(Ví dụ: Hex/Binary Engine, Backend Core, hoặc Module A)* | *(Ví dụ: Multi-language SAST, CLI, Frontend, hoặc Module B)* |
| **Thư mục code được GHI** | `src/module-a/**`<br>`crates/core/src/binary/**` | `src/module-b/**`<br>`crates/core/src/sast/**`, `crates/cli/**` |
| **Sổ cái (Ledger) được GHI** | `docs/progress/PHASE_LEDGER.md` | `artifacts/dual-lane/LANE2_LEDGER.md` |
| **Handoff & Artifacts** | `docs/progress/handoffs/LANE1-*_HANDOFF.md` | `artifacts/dual-lane/handoffs/LANE2-*_HANDOFF.md` |
| **Thư mục Build Cargo (nếu là Rust)** | `target/` mặc định | `%TEMP%\codex-lane2-target` (`CARGO_TARGET_DIR`) |
| **Quyền ĐỌC chéo (Read-Only)** | Đọc `LANE2_LEDGER.md` ở đầu mỗi pha | Đọc `PHASE_LEDGER.md` & handoff mới nhất của Luồng 1 ở đầu mỗi pha |

## 2. Hợp đồng giao tiếp chung (Shared Interfaces)

Liệt kê các kiểu dữ liệu / API / Schema mà cả 2 luồng cùng sử dụng (quy tắc: **chỉ thêm mới tương thích ngược, không tự ý phá vỡ field cũ**):

- Shared Types / Schema: `...`
- Shared API / Output Format: `...`

## 3. Trạng thái đồng bộ gần nhất (Snapshot)

- **LUỒNG 1 (`LANE_1`):** *(Cập nhật 1 dòng tóm tắt sau khi đóng mỗi pha)*
- **LUỒNG 2 (`LANE_2`):** *(Cập nhật 1 dòng tóm tắt sau khi đóng mỗi pha)*
