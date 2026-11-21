# Cẩm nang Xử lý Nhanh 9 Lỗi Thực Chiến (Troubleshooting)

> **Tác giả:** Lê Hoàng Ngọc Tươi | **Dự án:** Codex Dual-Lane & Security Kit (Apache License 2.0)

---

### Lỗi 1: `Error: this CLI has no complete local package ... rerun with --no-daemon`
* **Khi nào gặp:** Khi gọi trực tiếp tệp `codex.exe` đi kèm gói Microsoft Store (`WindowsApps\OpenAI.Codex_*`) trên PowerShell/CMD.
* **Nguyên nhân:** Mặc định `codex.exe` bật `daemon_auto_start = true` và đi tìm background server của bản Desktop.
* **Cách sửa:** Mở `%USERPROFILE%\.codex-official\config.toml`, thêm dưới mục `[features]`:
  ```toml
  [features]
  daemon_auto_start = false
  ```
  *(Script `setup-dual-lane.ps1` tự động dò bằng `codex features list` và thêm dòng này khi phiên bản Codex của bạn hỗ trợ).*

---

### Lỗi 2: `This session has reached the limit of 100 requests. Please start a new session to continue.`
* **Khi nào gặp:** Khi dùng cổng API trung gian giới hạn 100 lượt request cho mỗi `thread_id`.
* **Có bị mất code đã sửa không?** **KHÔNG!** Toàn bộ tệp code đã ghi xuống ổ cứng vẫn còn nguyên vẹn (tuyệt đối **không bấm nút "Hoàn tác / Undo"** trên giao diện).
* **Cách xử lý chuẩn:**
  1. Commit các thay đổi hiện tại vào Git để khóa an toàn.
  2. Gõ `/new` (hoặc tạo đoạn chat mới) — bộ đếm sẽ reset về `0/100`.
  3. Nhắn agent đọc lại tệp sổ cái (`PHASE_LEDGER.md` / `DUAL_LANE_BRIDGE.md`) và handoff mới nhất để nối tiếp chính xác 100%.
  4. *(Mẹo chạy nhiều pha không đụng trần 100 request)*: Dùng vòng lặp `codex exec` để mỗi pha tự chạy trong 1 phiên mới tinh (`0/100`):
     ```powershell
     1..3 | ForEach-Object {
         codex exec "Đọc ledger và handoff mới nhất, làm đúng 1 pha tiếp theo rồi cập nhật handoff và kết thúc."
     }
     ```

---

### Lỗi 3: Mở `codex resume` trên CLI chính chủ nhưng không thấy các phiên đã ghim (`Pinned`) từ Desktop App
* **Nguyên nhân:**
  1. Thư mục `sessions/` được nối chung qua Junction/symlink nhưng bảng metadata (`session_index.jsonl`, `state_*.sqlite`, `goals_*.sqlite`) nằm riêng ở từng `CODEX_HOME`.
  2. `codex resume` mặc định lọc theo thư mục làm việc hiện tại (`cwd`) và `model_provider` khớp cấu hình hiện tại (`openai` chữ thường vs `OpenAI` chữ hoa).
* **Cách sửa:** Khởi chạy `codex` tối thiểu 1 lần để khởi tạo `state_*.sqlite` ở Luồng 2, rồi chạy lệnh đồng bộ kèm đường dẫn dự án (có thể thêm `--pinned-only` nếu chỉ muốn đồng bộ các phiên đã ghim):
  ```powershell
  python .\scripts\sync-sessions.py --repo "C:\Projects\my-app" --pinned-only
  ```
  Hoặc mở danh sách toàn bộ mọi thư mục bằng `codex resume --all`.

---

### Lỗi 4: Agent cứ mỗi lần chạy lệnh lại dừng hỏi duyệt (`mỗi lần gọi mỗi lần hỏi`)
* **Nguyên nhân:** Tệp `config.toml` đang dùng mặc định an toàn `approval_policy = "on-request"` hoặc phiên cũ trong `state_*.sqlite` vẫn lưu `approval_mode = 'on-request'`.
* **Cách sửa:**
  * Nếu đang mở sẵn TUI: gõ `/permissions` trong khung chat để chuyển chế độ tạm thời.
  * Nếu bạn chủ động chạy tác vụ tự động trong môi trường đã cô lập và đã có **Khiên Git** (`git commit` checkpoint): cài lại với `-ApprovalPolicy never` (Windows) / `--approval-policy never` (Unix), hoặc đổi `approval_policy = "never"` trong `config.toml` *(vẫn giữ nguyên `sandbox_mode = "workspace-write"`, `network_access = false` và `rules/default.rules`)*.
  * Nếu mở lại phiên cũ: chạy lại `python .\scripts\sync-sessions.py --approval-mode never` để đồng bộ thuộc tính cho các phiên cũ.

---

### Lỗi 5: Cách đổi Model trong Codex CLI
* **Đổi ngay trong khung chat TUI:** Gõ `/model` rồi dùng phím mũi tên chọn model tài khoản của bạn hỗ trợ và mức reasoning (`low` / `medium` / `high` / `ultra`).
* **Chọn model ngay khi khởi chạy trên Terminal:**
  ```powershell
  codex -m <model-slug>
  codex -m <model-slug> resume
  ```
* **Đổi mặc định vĩnh viễn:** Chạy lại `setup-dual-lane.ps1` với `-OfficialModel "<model-slug>"` hoặc chỉnh dòng `model = "..."` trong `~/.codex-official/config.toml` *(để trống nếu muốn Codex tự dùng mặc định theo gói tài khoản)*.

---

### Lỗi 6: `Blocking waiting for file lock on build directory` khi 2 agent Rust cùng chạy `cargo test`
* **Nguyên nhân:** Hai tiến trình Cargo cùng ghi vào 1 thư mục `target/` duy nhất.
* **Cách sửa:** Luôn chạy Luồng 2 qua lệnh `codex` (wrapper và `config.toml` của Luồng 2 tự đặt `CARGO_TARGET_DIR`: mặc định `%TEMP%\codex-lane2-target` trên Windows hoặc `${TMPDIR:-/tmp}/codex-lane2-target` trên macOS/Linux/WSL, tách hoàn toàn khỏi `target/` của Luồng 1 và không làm bẩn `git status`). Nếu ổ `C:` ít dung lượng trống, truyền `-CargoTargetDir "D:\codex-lane2-target"` (Windows) hoặc `CODEX_CARGO_TARGET_DIR=/path/to/target` (Unix).

---

### Lỗi 7: Windows Defender báo cảnh báo mã độc trên tệp `~/.codex/sessions/.../rollout-*.jsonl` khi làm dự án an ninh / SAST
* **Nguyên nhân:** Khi agent đọc tĩnh các tệp unit test hoặc tập mẫu chứa chuỗi giả lập webshell (vd `Backdoor:PHP/...`), Codex ghi nguyên văn kết quả đọc text vào log hội thoại `.jsonl`. Trình diệt virus quét trúng chữ ký tĩnh trong tệp log nên báo nhầm (False Positive) — **không phải agent đã thực thi mã độc**.
* **Cách kiểm chứng nhanh (PowerShell):**
  ```powershell
  Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 3 InitialDetectionTime,ProcessName,Resources | Format-List
  ```
  Nếu `Resources` chỉ trỏ tới tệp `*.jsonl` (log văn bản) thì không có mã thực thi nào chạy.
* **Cách xử lý an toàn:**
  1. Xác nhận đã bật `[sandbox_workspace_write] network_access = false`, `default.rules` chặn LOLBins/interpreter và `AGENTS.md` có luật `Static-Analysis-Only Isolation`.
  2. **Không bấm Quarantine/Remove lên tệp `.jsonl` khi phiên đó đang chạy**, tránh đứt mạch lịch sử đang ghi. Đợi phiên kết thúc pha hiện tại $\rightarrow$ mở phiên mới `/new` $\rightarrow$ rồi dọn tệp log cũ (hoặc chọn **Allow on device** riêng cho tệp log nếu bạn chắc chắn đó là chuỗi test tĩnh của mình).

---

### Lỗi 8: `doctor.ps1` báo `[WARN] kernel_acl=EXPOSED(...)` sau khi chạy `codex features` hoặc đổi Settings trên Codex Desktop (Windows)
* **Nguyên nhân kỹ thuật (Giới hạn OS/Codex runtime):**
  1. Thư mục `~/.codex` / `~/.codex-official` có thể mang quyền kế thừa **`CodexSandboxUsers:(OI)(CI)(RX)`** do sandbox Windows của Codex tạo ra.
  2. Mỗi khi Codex CLI hoặc Codex Desktop cập nhật `config.toml` (vd sau `codex features enable ...`, tin cậy dự án mới, hoặc sửa Settings trong App) hay làm mới `auth.json` bằng cơ chế **atomic replace** (tạo tệp tạm rồi đổi tên đè lên tệp cũ), Windows cấp lại DACL kế thừa từ thư mục cha — làm mất khóa `icacls` cũ trên tệp đó.
* **Cách khắc phục & Phòng ngừa bền vững:**
  1. **Khóa lại ngay bằng quy trình `icacls.exe` 2 bước** (hoặc chạy lại `.\scripts\setup-dual-lane.ps1`):
     ```powershell
     foreach ($f in @("$env:USERPROFILE\.codex\auth.json","$env:USERPROFILE\.codex\config.toml","$env:USERPROFILE\.codex-official\auth.json","$env:USERPROFILE\.codex-official\config.toml")) {
         if (Test-Path -LiteralPath $f) {
             icacls $f /inheritance:d
             icacls $f /remove:g "CodexSandboxUsers"
         }
     }
     ```
     *(Lưu ý: Bắt buộc chạy 2 lệnh tuần tự — `/inheritance:d` trước để chuyển ACE kế thừa thành tường minh, rồi `/remove:g "CodexSandboxUsers"` mới gỡ được quyền đọc của sandbox).*
  2. **Khuyến nghị vệ sinh bí mật bền vững nhất:** Thêm `cli_auth_credentials_store = "keyring"` vào `config.toml` (nếu phiên bản Codex của bạn hỗ trợ) để lưu token đăng nhập trong OS Keyring thay vì `auth.json`, và luôn dùng `env_key` thay cho plaintext API key.

---

### Lỗi 9: Cách khôi phục / gỡ bỏ hoàn toàn mà không làm mất lịch sử phiên trong `~/.codex`
* **Cảnh báo quan trọng:** Các thư mục `memories`, `memories_v2`, `sessions`, `archived_sessions`, `skills`, `plugins` bên trong `~/.codex-official` là **NTFS Directory Junction** (Windows) hoặc **symlink** (macOS/Linux/WSL) trỏ về `~/.codex`. **Tuyệt đối không dùng công cụ xóa đệ quy bừa bãi lên `~/.codex-official` trước khi tháo các liên kết này!**
* **Cách gỡ chuẩn và an toàn nhất (tự động kiểm chứng SHA-256 & tháo liên kết trước):**
  * **Windows:**
    ```powershell
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1 -DryRun
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1 -RemoveLane2Home
    ```
  * **macOS / Linux / WSL:**
    ```bash
    ./scripts/restore-original.sh --dry-run
    ./scripts/restore-original.sh --remove-lane2-home
    ```
