# Cẩm nang Xử lý Nhanh 7 Lỗi Thực Chiến (Troubleshooting)

> **Tác giả:** Lê Hoàng Ngọc Tươi | **Dự án:** Codex Dual-Lane & Security Kit (Apache License 2.0)

---

### Lỗi 1: `Error: this CLI has no complete local package ... rerun with --no-daemon`
* **Khi nào gặp:** Khi gọi trực tiếp file `codex.exe` đi kèm gói Microsoft Store (`WindowsApps\OpenAI.Codex_*`) trên PowerShell/CMD.
* **Nguyên nhân:** Mặc định `codex.exe` bật `daemon_auto_start = true` và đi tìm background server của bản Desktop.
* **Cách sửa:** Mở `%USERPROFILE%\.codex-official\config.toml`, thêm vào dưới mục `[features]`:
  ```toml
  [features]
  daemon_auto_start = false
  ```
  *(Script `setup-dual-lane.ps1` đã tự thêm sẵn dòng này).*

---

### Lỗi 2: `This session has reached the limit of 100 requests. Please start a new session to continue.`
* **Khi nào gặp:** Khi dùng cổng API trung gian giới hạn 100 lượt request cho mỗi `thread_id`.
* **Có bị mất code đã sửa không?** **KHÔNG!** Toàn bộ file code đã ghi xuống ổ cứng vẫn còn nguyên vẹn (chỉ tuyệt đối **không bấm nút "Hoàn tác / Undo"** trên giao diện).
* **Cách xử lý chuẩn:**
  1. Commit các thay đổi hiện tại vào Git để khóa an toàn.
  2. Gõ `/new` (hoặc tạo đoạn chat mới) — bộ đếm sẽ reset về `0/100`.
  3. Nhắn agent đọc lại file sổ cái (`PHASE_LEDGER.md` / `DUAL_LANE_BRIDGE.md`) và handoff mới nhất để nối tiếp chính xác 100%.
  4. *(Mẹo chạy nhiều pha không đụng trần 100 request)*: Dùng vòng lặp `codex exec` để mỗi pha tự chạy trong 1 phiên mới tinh (`0/100`):
     ```powershell
     1..3 | ForEach-Object {
         codex exec "Đọc ledger và handoff mới nhất, làm đúng 1 pha tiếp theo rồi cập nhật handoff và kết thúc."
     }
     ```

---

### Lỗi 3: Mở `codex resume` trên CLI chính chủ nhưng không thấy các phiên đã ghim (`Pinned`) từ Desktop App
* **Nguyên nhân:**
  1. Thư mục `sessions/` được nối chung qua Junction nhưng bảng metadata (`session_index.jsonl`, `state_5.sqlite`, `goals_1.sqlite`) nằm riêng ở từng `CODEX_HOME`.
  2. `codex resume` mặc định lọc theo thư mục làm việc hiện tại (`cwd`) và `model_provider` khớp cấu hình hiện tại (`openai` chữ thường vs `OpenAI` chữ hoa).
* **Cách sửa:** Chạy lệnh đồng bộ kèm đường dẫn dự án:
  ```powershell
  python .\scripts\sync-sessions.py --repo "D:\duong-dan\du-an-cua-ban"
  ```
  Hoặc mở danh sách toàn bộ mọi thư mục bằng `codex resume --all`.

---

### Lỗi 4: Agent cứ mỗi lần chạy lệnh lại dừng hỏi duyệt (`mỗi lần gọi mỗi lần hỏi`)
* **Nguyên nhân:** File `config.toml` đang để `approval_policy = "on-request"` hoặc phiên cũ trong `state_5.sqlite` vẫn lưu `approval_mode = 'on-request'`.
* **Cách sửa:**
  * Đổi `approval_policy = "never"` trong `config.toml` (vẫn an toàn nhờ `sandbox_mode = "workspace-write"` và tường lửa `rules/default.rules`).
  * Nếu đang mở sẵn TUI: gõ `/permissions` trong khung chat để chuyển chế độ ngay lập tức.
  * Nếu mở lại phiên cũ: chạy lại `python .\scripts\sync-sessions.py --approval-mode never` để cập nhật luôn cho các phiên cũ.

---

### Lỗi 5: Cách đổi Model trong Codex CLI
* **Đổi ngay trong khung chat TUI:** Gõ `/model` rồi dùng phím mũi tên chọn model và mức reasoning (`low` / `medium` / `high` / `ultra`).
* **Chọn model ngay khi khởi chạy trên Terminal:**
  ```powershell
  codex -m gpt-6.2-sol
  codex -m gpt-6.2-sol resume
  ```
* **Đổi mặc định vĩnh viễn:** Sửa dòng `model = "..."` trong `%USERPROFILE%\.codex-official\config.toml`.

---

### Lỗi 6: `Blocking waiting for file lock on build directory` khi 2 agent Rust cùng chạy `cargo test`
* **Nguyên nhân:** Hai tiến trình Cargo cùng ghi vào 1 thư mục `target/` duy nhất.
* **Cách sửa:** Luôn chạy Luồng 2 qua lệnh `codex` (wrapper `codex.cmd` và `config.toml` của Luồng 2 tự đặt `CARGO_TARGET_DIR=%TEMP%\codex-lane2-target`, tách hoàn toàn khỏi `target/` mặc định của Luồng 1 và nằm ngoài repo nên không làm bẩn `git status`).

---

### Lỗi 7: Windows Defender báo cảnh báo mã độc trên tệp `~/.codex/sessions/.../rollout-*.jsonl` khi làm dự án an ninh / SAST
* **Nguyên nhân:** Khi agent đọc tĩnh các file unit test hoặc tập mẫu chứa chuỗi giả lập webshell (ví dụ `Backdoor:PHP/...`), Codex ghi nguyên văn kết quả đọc text vào log hội thoại `.jsonl`. Trình diệt virus quét trúng chuỗi tĩnh trong file log nên báo nhầm (False Positive) — **không phải agent đã thực thi mã độc**.
* **Cách kiểm chứng nhanh (PowerShell):**
  ```powershell
  Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 3 InitialDetectionTime,ProcessName,Resources | Format-List
  ```
  Nếu `Resources` chỉ trỏ tới tệp `*.jsonl` (log văn bản) thì không có mã thực thi nào chạy.
* **Cách xử lý an toàn:**
  1. Đảm bảo đã cài phiên bản mới nhất của bộ kit (`[sandbox_workspace_write] network_access = false`, `default.rules` chặn `php/cscript/wscript/mshta/rundll32/Start-Process/iex`, và `AGENTS.md` có luật `Static-Analysis-Only Isolation`).
  2. **Không bấm Quarantine/Remove lên file `.jsonl` khi phiên đó đang chạy**, tránh đứt mạch lịch sử đang ghi. Có thể chọn **Allow on device** riêng cho file log đó, hoặc đợi phiên xong pha hiện tại $\rightarrow$ mở phiên mới `/new` $\rightarrow$ rồi dọn file log cũ.
