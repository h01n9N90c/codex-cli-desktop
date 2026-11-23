# Cẩm nang Xử lý Nhanh Các Lỗi Thực Chiến (Troubleshooting)

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
* **Cách sửa:** Khởi chạy `codex` tối thiểu 1 lần để khởi tạo `state_*.sqlite` ở Luồng 2, rồi đồng bộ bằng 1 trong 2 cách sau:
  * **Đồng bộ 2 chiều đầy đủ giữa GPT 1 (`~/.codex`) và Sandbox 2 (`~/.codex-official`) — khuyên dùng từ v1.4.0** *(có sao lưu SQLite trước khi ghi, bảo toàn `is_pinned = 1` và không bao giờ ghi đè dữ liệu `updated_at` mới hơn của GPT 1)*:
    ```powershell
    # Windows (hoặc gõ `codex-manage` rồi chọn mục [5]):
    .\scripts\codex-manager.ps1 -Action SyncHistory
    # Hoặc gọi trực tiếp Python (Windows / macOS / Linux / WSL):
    python .\scripts\sync-sessions.py --bidirectional --backup-target
    ```
  * **Hoặc chỉ đồng bộ 1 chiều các phiên đã ghim (`Pinned`) gắn với thư mục dự án hiện tại:**
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
  1. **Khóa nhanh lại ngay trong ~1 giây bằng `-ReapplyAclOnly`** (khuyên dùng — giữ nguyên bit-identical SHA-256 của `config.toml` & `auth.json`):
     ```powershell
     powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 -ReapplyAclOnly
     ```
     Hoặc chạy thủ công quy trình `icacls.exe` 2 bước tuần tự (`/inheritance:d` trước để chuyển ACE kế thừa thành tường minh, rồi `/remove:g "CodexSandboxUsers"`):
     ```powershell
     foreach ($f in @("$env:USERPROFILE\.codex\auth.json","$env:USERPROFILE\.codex\config.toml","$env:USERPROFILE\.codex-official\auth.json","$env:USERPROFILE\.codex-official\config.toml")) {
         if (Test-Path -LiteralPath $f) {
             icacls $f /inheritance:d
             icacls $f /remove:g "CodexSandboxUsers"
         }
     }
     ```
  2. **Khuyến nghị vệ sinh bí mật bền vững nhất:** Thêm `cli_auth_credentials_store = "keyring"` vào `config.toml` (nếu phiên bản Codex của bạn hỗ trợ) để lưu token đăng nhập trong OS Keyring thay vì `auth.json`, và luôn dùng `env_key` thay cho plaintext API key.

---

### Lỗi 9: Cách khôi phục / gỡ bỏ hoàn toàn (hoặc phục hồi sau khi cài đặt bị ngắt giữa chừng) mà không làm mất lịch sử phiên hay link có trước
* **Cảnh báo quan trọng:** Các thư mục `memories`, `memories_v2`, `sessions`, `archived_sessions`, `skills`, `plugins` bên trong `~/.codex-official` là **NTFS Directory Junction** (Windows) hoặc **symlink** (macOS/Linux/WSL) trỏ về `~/.codex`. **Tuyệt đối không dùng công cụ xóa đệ quy bừa bãi lên `~/.codex-official` trước khi tháo các liên kết này!**
* **Bảo toàn liên kết có trước, khôi phục đúng thư mục backup & preflight fail-closed (v1.3.1):**
  * Từ v1.3.1 (`SchemaVersion = 2` / `schema_version=2`), manifest ghi nhận rõ `SharedLinkRecords` / dòng `L` (`PriorState`: `absent`, `preexisting_link`, `preexisting_dir` và `CreatedByKit`): mọi Junction/symlink do bạn tự tạo từ trước khi cài kit sẽ **được giữ nguyên 100%** khi rollback; các thư mục gốc được khôi phục từ **đúng đường dẫn `BackupDirPath` / `dir_bkp` ghi trong manifest** (không đoán mò theo tên wildcard `.backup-*`).
  * Nếu bạn vô tình xóa/di chuyển mất một tệp hoặc thư mục `.backup-*` bắt buộc, bước **Preflight Fail-Closed** của `restore-original.*` sẽ dừng ngay lập tức với mã thoát `1` **trước khi tháo bất kỳ Junction/symlink nào hay sửa tệp trên đĩa** (0 tác dụng phụ bán phần).
* **Phục hồi khi cài đặt bị ngắt giữa chừng (`Ctrl+C` / lỗi đột ngột):** Bộ cài ghi nhật ký rollback tăng dần sau từng thao tác (`.rollback/latest.json` với `Completed: false` trên Windows / `.rollback/latest.tsv` với `# status=in-progress` trên Unix). Nếu `doctor.ps1` / `doctor.sh` báo `[WARN] Rollback Journal`, hãy chạy ngay `restore-original.*` bên dưới để hoàn nguyên sạch toàn bộ thay đổi bán phần rồi cài lại.
* **Cách gỡ chuẩn và an toàn nhất — Xóa Sandbox 2 KHÔNG mất 1 cuộc chat nào (v1.4.0, khuyên dùng):**
  * Dùng **`codex-manage`** (mục `[6]`) hoặc chạy trực tiếp `RemoveSandbox2` / `remove-sandbox2`. Công cụ **bắt buộc chạy bước cứu hộ ngược fail-closed** (`sync-sessions.py --source <Lane2> --target <Lane1> --rescue-shared-files --backup-target`) để đưa 100% phiên chat, `Pinned`, `Goals` và mọi tệp rollout/memory cục bộ (nếu không phải Junction/symlink) về **GPT 1 (`~/.codex`) trước**, rồi mới gọi `restore-original.* -RemoveLane2Home` / `--remove-lane2-home` tháo sạch liên kết và xóa `~/.codex-official` (nếu bước cứu hộ lỗi, Sandbox 2 sẽ không bị xóa!):
    * **Windows:**
      ```powershell
      .\scripts\codex-manager.ps1 -Action RemoveSandbox2 -DryRun
      .\scripts\codex-manager.ps1 -Action RemoveSandbox2
      ```
    * **macOS / Linux / WSL:**
      ```bash
      ./scripts/codex-manager.sh --action remove-sandbox2 --dry-run
      ./scripts/codex-manager.sh --action remove-sandbox2
      ```
* **Hoặc khôi phục thuần theo Snapshot SHA-256 (chỉ rollback cấu hình/launcher, không cần cứu hộ thêm nếu đã đồng bộ xong):**
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

---

### Lỗi 10: Wrapper `codex` báo `[FAIL] Lane 2 worktree ... is missing or inaccessible` (hoặc `cd failed`) và từ chối chạy
* **Khi nào gặp:** Bạn đã cài với cờ `-UseGitWorktree` / `--use-git-worktree`, sau đó thư mục worktree `<repo>-lane2` bị xóa, di chuyển, bị thay bằng tệp thường/symlink, hoặc không thể truy cập (`cd` thất bại).
* **Tại sao lại từ chối chạy thay vì chạy ở repo chính?** Đây là **tính năng bảo vệ Hard Fail-Closed**: wrapper Luồng 2 cố ý dừng với mã thoát `1` và không khởi chạy `codex` để ngăn agent Luồng 2 âm thầm fallback về ghi đè lên cây làm việc của Luồng 1 trong repo chính.
* **Cách xử lý chuẩn:**
  1. **Tạo lại worktree Luồng 2 (khuyên dùng):** Chạy lại bộ cài với `-UseGitWorktree` (Windows) hoặc `--use-git-worktree` (Unix) để dựng lại worktree chuẩn và cập nhật wrapper.
  2. **Tạm tắt tự động đổi thư mục (chỉ khi thực sự cần):** Đặt `CODEX_NO_AUTO_WORKTREE_CD=1` trong shell hiện tại (lưu ý: cơ chế chặn đối số `-C`/`--cd`/`--add-dir` trỏ vào repo chính vẫn luôn bật fail-closed).
  3. **Gỡ chế độ worktree:** Chạy lại `setup-dual-lane.*` **không kèm** cờ `-UseGitWorktree` / `--use-git-worktree`.

---

### Lỗi 11 *(Câu hỏi thực tế)*: Làm sao giữ Codex Desktop (`~/.codex`, Luồng 1 — `acc chính`) toàn quyền như trước (không đụng 1 byte cấu hình), tận dụng kế thừa chỉ-đọc tài nguyên sang Codex CLI (`~/.codex-official`, Luồng 2) để dùng cả Login OAuth lẫn API Key mà agent vẫn tự do nắm cây thư mục & sửa/xóa file?
* **1. Giữ Codex Desktop (`~/.codex`, Luồng 1) toàn quyền như trước (`acc chính`) & Kế thừa chỉ-đọc (`Read-Only Harvesting`):**
  * Khi cài mặc định (hoặc dùng `-ConfigureCliGateway` / `-GatewayTargetLane Lane2` trên Windows hay `--configure-cli-gateway` / `--gateway-target-lane lane2` trên Unix), bộ kit **tuyệt đối không chạm vào `~/.codex/config.toml` hay `~/.codex/auth.json`**, giữ nguyên 100% quyền hạn, cấu hình và mạng gốc của Codex Desktop. Đồng thời bộ cài đọc chỉ-đọc `~/.codex/config.toml` để tự động kế thừa toàn bộ danh sách `[projects."..."]` đã `trusted` sang `~/.codex-official/config.toml` (kèm tùy chọn `-ShareAuthToLane2` / `--share-auth-to-lane2` để chép `auth.json` sang Luồng 2 với khóa ACL / `chmod 600` và theo dõi rollback).
  * Trong `AGENTS.lane1.md` (Rule 4 & Rule 6), Codex Desktop được khẳng định rõ **toàn quyền như trước** trên toàn bộ cây thư mục dự án (đọc, ghi, tạo, sửa, di chuyển, xóa file, build & test toàn dự án mặc định; chỉ phân chia thư mục nếu bạn chủ động khai báo nhiệm vụ song song trong `DUAL_LANE_BRIDGE.md`).
* **2. Dùng cả Login OAuth lẫn API Key trên Codex CLI (`~/.codex-official`, Luồng 2) trên mọi Shell (PowerShell / CMD / Git Bash / MSYS2 / Unix):**
  * **Đăng nhập OAuth (`auth.json` / `keyring`):** Chạy `codex login` (hoặc dùng `-ShareAuthToLane2` / `--share-auth-to-lane2` khi cài).
  * **Dùng API Key / Gateway 1 chạm (`env_key`):** Cài với `-ConfigureCliGateway -GatewayBaseUrl "https://<endpoint>/v1" -CliApiKeyEnv "CODEX_CLI_API_KEY" -PromptGatewayApiKey` (Windows) hoặc `--configure-cli-gateway --gateway-base-url "https://<endpoint>/v1" --cli-api-key-env CODEX_CLI_API_KEY` (Unix), hoặc nạp key chuẩn bằng `$env:OPENAI_API_KEY | codex login --with-api-key`. Trên Windows, bộ cài sinh cả `.cmd` lẫn POSIX shim không đuôi (`codex`, `codex-official`, `codex-t3`) nên bạn có thể gõ `codex` trực tiếp trong cả PowerShell, CMD lẫn Git Bash / MSYS2.
* **3. Toàn quyền nắm cây thư mục & thao tác File CRUD trong Workspace:**
  * Bên trong thư mục dự án (`workspace-write`), toàn bộ công cụ duyệt cây thư mục (`rg --files`, `git status`, `Get-ChildItem`, `find`) và thao tác file CRUD (`apply_patch`, `Set-Content`, `Remove-Item`, `rm`, `mv`, `cp`, `mkdir`) đều được phép 100% (`matchedRules: []` trong `default.rules`). Quy tắc `Static-Analysis-Only` chỉ cấm **thực thi/kích nổ** tệp mẫu mã độc/payload bên thứ 3, tuyệt đối không hạn chế việc đọc/tạo/sửa/xóa code của dự án.

---

### Lỗi 12 *(Câu hỏi thực tế — v1.4.0)*: Làm sao đổi nhanh API Key OpenAI / Custom Gateway, chuyển sang Đăng nhập chính thức, kiểm tra API Key còn sống hay hết hạn (`401`/`429`), hoặc kiểm tra nhanh trạng thái cả GPT 1 & Sandbox 2 mà không lộ secret?
* **Giải pháp 1 chạm — Mở Trung tâm Điều khiển Sandbox 2 (`codex-manage`):**
  ```powershell
  codex-manage
  ```
* **Đổi sang OpenAI / GPT API Key chính chủ (không để lại xung đột `model_provider` bên thứ 3):**
  * Chạy `.\scripts\codex-manager.ps1 -Action ApiGpt` *(Unix: `./scripts/codex-manager.sh --action api-gpt`)*: nhập ẩn đúng 1 key (tuyệt đối không truyền key trên dòng lệnh), script tự sao lưu `config.toml`, dọn `model_provider` bên thứ 3, nạp key qua stdin vào `codex login --with-api-key`, khóa lại NTFS DACL / `chmod 600` và đồng bộ lịch sử 2 chiều.
* **Chỉnh cổng API bên thứ 3 / Custom Gateway trực tiếp trong `~/.codex-official/config.toml`:**
  * Chạy `.\scripts\codex-manager.ps1 -Action ApiOther` *(Unix: `./scripts/codex-manager.sh --action api-other`)*: script tự sao lưu, mở thẳng `config.toml` kèm mẫu `env_key` an toàn, hậu kiểm cú pháp TOML (`tomllib`), cảnh báo nếu bạn lỡ dán plaintext `api_key`, rồi tự khóa lại NTFS DACL / `chmod 600`.
* **Chuyển sang Đăng nhập chính thức (`codex login`):**
  * Chạy `.\scripts\codex-manager.ps1 -Action Login` *(thêm `-DeviceAuth` nếu môi trường không có trình duyệt; Unix: `./scripts/codex-manager.sh --action login --device-auth`)*.
* **Kiểm tra API Key sống/chết & đọc mã trạng thái `/models` mà không lộ key:**
  * Chạy `.\scripts\codex-manager.ps1 -Action CheckApiKey -OnlineCheck` *(Unix: `./scripts/codex-manager.sh --action check-api-key --online-check`)*:
    * **`VALID (HTTP 200, N models)`:** Key hợp lệ và endpoint phản hồi tốt.
    * **`INVALID/EXPIRED (HTTP 401/403)`:** Key sai, bị thu hồi, hoặc sai `base_url`/quyền project — chạy lại `ApiGpt` hoặc `ApiOther` để cập nhật.
    * **`QUOTA/RATE_LIMITED (HTTP 429)`:** Tài khoản/API key hết hạn mức thanh toán hoặc bị giới hạn tốc độ — kiểm tra billing trên trang nhà cung cấp.
    * **`NETWORK_ERROR`:** Lỗi mạng, proxy hoặc sai `base_url` (lưu ý: `CheckApiKey` mặc định chạy offline khi không truyền `-OnlineCheck`/`--online-check`).
* **Kiểm tra nhanh trạng thái cả 2 tài khoản (GPT 1 Desktop & Sandbox 2 CLI — chỉ đọc 100%):**
  * Chạy `.\scripts\codex-manager.ps1 -Action CheckAccounts` *(Unix: `./scripts/codex-manager.sh --action check-accounts`)* để xem `codex login status`, `auth_mode`, `model_provider`, `env_key`, 6 liên kết dùng chung, số lượng phiên và trạng thái ACL / `0600` của cả hai luồng mà không làm thay đổi 1 byte nào ở GPT 1.
