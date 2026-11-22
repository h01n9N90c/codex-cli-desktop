# Dual-Lane Coordination Bridge (`LANE 1` <-> `LANE 2`)

<!--
HƯỚNG DẪN TÙY BIẾN & QUY TẮC AN TOÀN CHO NGƯỜI DÙNG CUỐI (End-User Guide):
1. Nơi đặt file: Chép mẫu này vào dự án của bạn tại `artifacts/dual-lane/DUAL_LANE_BRIDGE.md`
   (hoặc chạy bộ cài với cờ `-InstallBridgeTemplate` trên Windows / `--install-bridge` trên Unix).
2. PHẦN CẦN TÙY BIẾN (bắt buộc điền theo cấu trúc repo của bạn):
   - Mục 1: Điền chính xác nhiệm vụ & thư mục được phép GHI của Luồng 1 và Luồng 2 (không giao nhau!).
   - Mục 2: Liệt kê schema / interface / output format dùng chung để hai luồng không phá vỡ hợp đồng của nhau.
   - Mục 3: Cập nhật 1 dòng tóm tắt sau mỗi mốc (milestone) để luồng còn lại nắm tiến độ.
3. QUY TẮC AN TOÀN PHẢI GIỮ NGUYÊN (KHÔNG XÓA):
   - Giữ nguyên nguyên tắc Zero-Collision (chỉ ghi trong vùng sở hữu, chỉ đọc chéo sổ cái của luồng kia).
   - Giữ nguyên nguyên tắc Static-Analysis-Only (chỉ phân tích tĩnh nếu repo có tệp mẫu/binary/payload).
   - KHÔNG BAO GIỜ ghi API key, token, mật khẩu hay đường dẫn nhạy cảm vào tệp cầu nối này.
   - Lưu ý ranh giới kỹ thuật: Khi 2 luồng dùng chung 1 thư mục làm việc (worktree), bảng phân vùng bên
     dưới là **Ranh giới mềm (Soft Prompt Boundary)**. Nếu cần **Ranh giới cứng ở cấp OS Sandbox**, hãy
     khởi tạo worktree riêng cho Luồng 2 bằng `-UseGitWorktree` (Windows) hoặc `--use-git-worktree` (Unix).
-->

> **Cách dùng nhanh:** Điền các thư mục sở hữu không giao nhau vào bảng bên dưới để **Luồng 1 (`LANE_1`)** và **Luồng 2 (`LANE_2`)** phối hợp song song mà không ghi đè tệp của nhau.

## 1. Phân vùng quyền sở hữu (Zero-Collision Ownership)

| Hạng mục | **LUỒNG 1 (`LANE_1` — Codex Desktop / Tài khoản Chính `acc chính` / `codex-t3`)** | **LUỒNG 2 (`LANE_2` — Codex CLI `codex` / Linh hoạt Đăng nhập OAuth & API Key)** |
| :--- | :--- | :--- |
| **Vai trò & Xác thực** | **Codex Desktop App** (`~/.codex`, tài khoản chính `acc chính`, hoặc cổng phụ khi cấu hình `-GatewayTargetLane Lane1\|Both`) | **Codex CLI** (`~/.codex-official`, hỗ trợ **cả Đăng nhập OAuth `codex login` lẫn API Key / Gateway** qua `env_key` & `-GatewayTargetLane Lane2\|Both`) |
| **Nhiệm vụ chính** *(Tùy biến)* | *(Ví dụ: Backend Core, Binary/Parser Engine, hoặc Module A)* | *(Ví dụ: SAST/Analyzers, CLI, Frontend, hoặc Module B)* |
| **Thư mục code được GHI** *(Tùy biến — không giao nhau)* | `src/module-a/**`<br>`crates/core/src/module_a/**` | `src/module-b/**`<br>`crates/core/src/module_b/**`, `crates/cli/**` |
| **Sổ cái (Ledger) được GHI** *(Tùy biến)* | `docs/progress/PHASE_LEDGER.md` | `artifacts/dual-lane/LANE2_LEDGER.md` |
| **Handoff & Artifacts** *(Tùy biến)* | `docs/progress/handoffs/LANE1-*_HANDOFF.md` | `artifacts/dual-lane/handoffs/LANE2-*_HANDOFF.md` |
| **Thư mục Build Cargo (nếu là Rust)** *(Giữ mặc định)* | `target/` mặc định của repo | Windows: `%TEMP%\codex-lane2-target`<br>Unix/macOS: `${TMPDIR:-/tmp}/codex-lane2-target` (`CARGO_TARGET_DIR`) |
| **Quyền ĐỌC chéo (Read-Only)** *(Giữ nguyên)* | Chỉ đọc `LANE2_LEDGER.md` & handoff Luồng 2 ở đầu mỗi pha | Chỉ đọc `PHASE_LEDGER.md` & handoff Luồng 1 ở đầu mỗi pha |
| **Nắm bắt Cây Thư mục & Thao tác File CRUD (Full Workspace Directory Tree Mastery & File CRUD Authority)** | **Toàn quyền như trước trên Codex Desktop:** Mặc định nắm toàn bộ cây thư mục dự án (`rg --files`, `git status`, `Get-ChildItem`, `find`) và tự do đọc, ghi, tạo, sửa, di chuyển, xóa file, build & test trên toàn dự án (chỉ giới hạn theo phân vùng khi chạy song song với Luồng 2 theo bảng này) | Toàn quyền duyệt & nắm toàn bộ cây thư mục dự án (`rg --files`, `git status`, `Get-ChildItem`, `find`), tự do đọc, tạo mới, sửa, di chuyển và xóa file trong vùng sở hữu của Luồng 2 (`workspace-write`) |

## 2. Hợp đồng giao tiếp chung (Shared Interfaces) *(Tùy biến theo dự án)*

Liệt kê các kiểu dữ liệu / API / Schema mà cả 2 luồng cùng sử dụng (quy tắc bắt buộc: **chỉ thêm mới tương thích ngược, không tự ý đổi tên hoặc xóa field đang dùng chung**):

- **Shared Types / Schema:** `...`
- **Shared API / CLI Contract / Output Format:** `...`
- **Chính sách bảo mật & Toàn quyền Thao tác File trong Workspace (Giữ nguyên):**
  - Trong phạm vi dự án (`sandbox_mode = "workspace-write"`), agent được **toàn quyền nắm bắt toàn bộ cây thư mục** và **đọc, ghi, tạo, sửa, đổi tên, xóa file** dự án phục vụ lập trình (tuân thủ vùng sở hữu Zero-Collision ở Mục 1).
  - Mọi phân tích mẫu lỗ hổng/nhị phân bên thứ ba đều tuân thủ **Static-Analysis-Only** (chỉ cấm thực thi/kích nổ mẫu độc hại, không bao giờ hạn chế việc đọc/sửa/xóa mã nguồn dự án); không lưu secret/API key/token vào repo hay tệp cầu nối này.

## 3. Trạng thái đồng bộ gần nhất (Snapshot) *(Cập nhật sau mỗi pha)*

- **LUỒNG 1 (`LANE_1`):** *(Cập nhật 1 dòng tóm tắt sau khi đóng mỗi pha, kèm đường dẫn handoff nếu có)*
- **LUỒNG 2 (`LANE_2`):** *(Cập nhật 1 dòng tóm tắt sau khi đóng mỗi pha, kèm đường dẫn handoff nếu có)*
