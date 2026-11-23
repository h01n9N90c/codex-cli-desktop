# Hướng dẫn Chi tiết & Khai báo Mã nguồn / Công cụ (Manifest)

> **Tác giả:** **Lê Hoàng Ngọc Tươi** | **Giấy phép:** Apache License 2.0 ([LICENSE](../LICENSE) · [NOTICE](../NOTICE))  
> Tài liệu này minh bạch hóa **100% từng tệp mã nguồn, từng hàm thực thi, tham số dòng lệnh, đường dẫn đọc/ghi và giới hạn tác động** trong bộ **Codex Dual-Lane & Security Kit**, để bất kỳ lập trình viên hay đội kiểm duyệt an ninh nào cũng có thể kiểm chứng trước khi chạy.

---

## 1. Cam kết minh bạch an ninh (Những gì bộ công cụ TUYỆT ĐỐI KHÔNG làm)

* **Không gửi telemetry / không tải mã từ xa:** Toàn bộ script cài đặt (`setup-dual-lane.*`), chẩn đoán (`doctor.*`), khôi phục (`restore-original.*`) và đồng bộ (`sync-sessions.py`) chạy cục bộ 100% với **0 kết nối mạng**. Ngoại lệ duy nhất có kết nối mạng (tắt mặc định) là khi bạn **chủ động bật** chế độ kiểm tra sống API Key (`codex-manager.ps1 -Action CheckApiKey -OnlineCheck` hoặc `codex-manager.sh --action check-api-key --online-check`), chỉ gửi đúng 1 yêu cầu chỉ-đọc `GET <base_url>/models` trực tiếp tới endpoint API bạn đã cấu hình (không đưa key lên dòng lệnh `argv` hay in ra log).
* **Không đòi quyền Administrator bắt buộc:** Mọi thao tác (`Get-AppxPackage`, tạo NTFS Directory Junction trong `%USERPROFILE%`, sửa `User PATH`, đọc/ghi `~/.codex*`) đều chạy ở quyền người dùng thường.
* **Không chứa API key, token hay mock data:** Mọi thông số máy (phiên bản OS, ổ đĩa, NTFS, dung lượng trống, đường dẫn `codex`, danh sách feature flags, bảng cột SQLite) đều được đọc trực tiếp từ hệ thống thật tại thời điểm chạy.
* **Không xóa đè cấu hình gốc không sao lưu:** Mọi tệp cấu hình/rule/`AGENTS.md` cũ đều được sao lưu với hậu tố `.backup-yyyyMMdd-HHmmss` (kèm bản kiểm chứng SHA-256 trong `.rollback/latest.json` trên Windows hoặc `.rollback/latest.tsv` trên Unix) trước khi ghi.
* **Không sửa trạng thái nội bộ sandbox của Codex:** Không tự ý thay đổi `.sandbox\deny_read_acl_state.json` hay tệp runtime riêng của Codex.
* **Cảnh báo opt-in `-ShareAuthToLane2` / `--share-auth-to-lane2` (tắt mặc định):** Bộ cài **không bao giờ** tự sao chép `~/.codex/auth.json` sang Luồng 2 trừ khi bạn chủ động truyền cờ này. Việc bật cờ sẽ tạo **bản sao thứ 2 của `auth.json` (OAuth token)** tại `~/.codex-official/auth.json` (có khóa ACL / `chmod 600` và theo dõi rollback), phát cảnh báo `[WARN]` rõ ràng, và **nên tránh hoặc hết sức thận trọng khi Luồng 2 được cấu hình với cổng API bên thứ 3**.
* **Ranh giới minh bạch CI (Mock `codex`) vs. Codex Runtime thật:** **4/4 job xanh trên GitHub Actions CI** kiểm chứng script, bảo toàn `trust_level`, fail-closed worktree và rollback đa hệ điều hành bằng các binary `codex` giả lập (`mock codex`) — **không thay thế** cho việc chạy `scripts/doctor.ps1` / `scripts/doctor.sh` và tự kiểm chứng hành vi trên đúng phiên bản **Codex Desktop/CLI thật** đang cài trên máy bạn.

---

## 2. Khai báo chi tiết toàn bộ tệp mã nguồn & công cụ

### 2.1. Công cụ thực thi (`scripts/`)

| Tệp | Ngôn ngữ / Runtime | Vai trò chính | Đường dẫn ĐỌC | Đường dẫn GHI |
| :--- | :--- | :--- | :--- | :--- |
| [`scripts/setup-dual-lane.ps1`](../scripts/setup-dual-lane.ps1) | PowerShell 5.1+ / 7+ (Windows) | Bộ cài đặt chính 1 chạm cho Windows (hỗ trợ `-DryRun`/`-WhatIf`, `-ReapplyAclOnly`, `-CliMode Ask\|Config\|FullAccess` + `-ConfirmFullAccess`, alias `-ProjectRoot` & đường dẫn tương đối `-RepoPath .`, chuẩn hóa đường dẫn dài 8.3 qua `GetLongPathNameW`, kế thừa chỉ-đọc `[projects."..."]` từ `~/.codex/config.toml` với bảo toàn nghiêm ngặt `trust_level` + `-TrustRepoPath` opt-in + tùy chọn opt-in `-ShareAuthToLane2` tắt mặc định kèm `[WARN]`, merge không phá hủy `[features]`/`web_search`/TOML giữ trọn tính năng gốc Codex CLI + ghi nguyên tử, cấu hình 1 cờ `-ConfigureCliGateway` / `-CliApiKeyEnv`, kiểm tra fail-closed chống plaintext secret, khóa ACL `icacls` 2 bước, wrapper worktree fail-closed cứng, nhật ký rollback tăng dần SHA-256) | `Get-AppxPackage OpenAI.Codex`, `PATH`, `Get-Volume`, `codex features list`, `templates/*`, `config.toml` cũ (đọc chỉ-đọc Luồng 1) | `~/.codex-official/config.toml`, `~/.codex*/rules/default.rules`, `~/.codex*/AGENTS.md`, `~/.codex-official/.rollback/latest.json`, 6 NTFS Junctions, 4 wrapper `.cmd` + 4 POSIX shim không đuôi (`codex`, `codex-official`, `codex-t3`, `codex-manage`) trong `~/.local/bin/` |
| [`scripts/setup-dual-lane.sh`](../scripts/setup-dual-lane.sh) | Bash (`set -euo pipefail`, macOS / Linux / WSL) | Bộ cài đặt tương đương cho hệ Unix (hỗ trợ `--dry-run`, `--cli-mode ask\|config\|full-access` + `--confirm-full-access`, đường dẫn tương đối `--repo-path .`, kế thừa chỉ-đọc `[projects."..."]` từ `~/.codex/config.toml` với bảo toàn nghiêm ngặt `trust_level` + `--trust-repo-path` opt-in + tùy chọn opt-in `--share-auth-to-lane2` tắt mặc định kèm `[WARN]`, `--configure-cli-gateway` / `--cli-api-key-env`, `umask 077` / `chmod 700` / `chmod 600`, ghi nguyên tử `mktemp`, merge không phá hủy `[features]`/`web_search`/khóa top-level & section giữ trọn tính năng gốc Codex CLI, wrapper worktree fail-closed cứng, nhật ký rollback tăng dần 5 cột SHA-256 + `original_mode` tại `.rollback/latest.tsv`, `--install-bridge`, `--sync-sessions`, `--use-git-worktree`) | `type -ap codex`, `codex features list`, `templates/*`, `config.toml` cũ (đọc chỉ-đọc Luồng 1) | `~/.codex-official/config.toml`, `~/.codex-official/.rollback/latest.tsv`, 6 symlinks (`ln -s`), `rules/default.rules`, `AGENTS.md`, 4 wrapper shell (`codex`, `codex-official`, `codex-t3`, `codex-manage`) trong `~/.local/bin/` |
| [`scripts/codex-manager.ps1`](../scripts/codex-manager.ps1) | PowerShell 5.1+ / 7+ (Windows) | **Trung tâm Điều khiển Tương tác & CLI cho Sandbox 2** (`codex-manage`): menu 7 chức năng (hiển thị ngay chế độ quyền hiện hành) & cờ trực tiếp (`ApiGpt`, `ApiOther`, `Login`, `CheckApiKey` kèm tùy chọn `-OnlineCheck` probe HTTPS-only không redirect `/models`, `CheckAccounts` chỉ-đọc 2 luồng, `SyncHistory` 2 chiều, `RemoveSandbox2` cứu hộ 100% lịch sử chat về GPT 1 fail-closed trước khi gỡ Sandbox 2, và `SetCliMode` chuyển 3 chế độ quyền `Ask` / `Config` / `FullAccess` fail-closed có cảnh báo nguy hiểm); không bao giờ nhận plaintext key trên CLI argv hay in ra console | `~/.codex/{config.toml,auth.json,session_index.jsonl}` *(chỉ đọc)*, `~/.codex-official/{config.toml,auth.json,session_index.jsonl}`, biến môi trường `env_key` / `OPENAI_API_KEY`, `codex login status`, đích 6 NTFS Junction, `Get-Acl` | `~/.codex-official/{config.toml,auth.json,.backup-*}` *(chỉ khi chạy `ApiGpt`/`ApiOther`/`Login`/`SetCliMode` kèm khóa ACL 2 bước)*; đồng bộ lịch sử chat qua `sync-sessions.py --bidirectional --backup-target` / `--rescue-shared-files`; gỡ Sandbox 2 an toàn qua `restore-original.ps1 -RemoveLane2Home` |
| [`scripts/codex-manager.sh`](../scripts/codex-manager.sh) | Bash (`set -euo pipefail`, macOS / Linux / WSL) | **Trung tâm Điều khiển Tương tác & CLI tương đương cho Unix** (`codex-manage`): đầy đủ menu 7 chức năng & cờ `--action api-gpt\|api-other\|login\|check-api-key\|check-accounts\|sync-history\|remove-sandbox2\|set-cli-mode`, kiểm tra sống `/models` HTTPS-only không redirect qua Python `urllib` (env/stdin — không lộ trên `ps`/`curl` argv), chọn 3 chế độ quyền CLI (`ask`/`config`/`full-access` fail-closed với cảnh báo nguy hiểm), khóa `chmod 600` sau sửa/đăng nhập, đồng bộ 2 chiều và gỡ Sandbox 2 bảo toàn 100% lịch sử chat về GPT 1 | `~/.codex/{config.toml,auth.json,session_index.jsonl}` *(chỉ đọc)*, `~/.codex-official/{config.toml,auth.json,session_index.jsonl}`, `env_key` / `OPENAI_API_KEY`, `codex login status`, 6 symlink, quyền POSIX (`stat`) | `~/.codex-official/{config.toml,auth.json,.backup-*}` *(chỉ khi chạy `api-gpt`/`api-other`/`login`/`set-cli-mode` kèm `chmod 600`)*; đồng bộ lịch sử chat qua `sync-sessions.py`; gỡ Sandbox 2 an toàn qua `restore-original.sh --remove-lane2-home` |
| [`scripts/restore-original.ps1`](../scripts/restore-original.ps1) | PowerShell 5.1+ / 7+ (Windows) | **Khôi phục chính xác 1 chạm** về trạng thái gốc dựa trên manifest `.rollback/latest.json` (kể cả manifest bán phần `Completed: false` sau cài đặt bị ngắt) với preflight kiểm chứng **SHA-256**, chuẩn hóa đường dẫn dài 8.3, khóa phạm vi đường dẫn phía caller & chặn reparse point, idempotent nhiều lần chạy (hỗ trợ `-DryRun`/`-WhatIf`, `-SnapshotPath`, `-RemoveLane2Home`) | `~/.codex-official/.rollback/latest.json`, các bản `.backup-*`, mã băm SHA-256 | Tháo an toàn 6 NTFS Junction bằng Win32 `Directory.Delete` trước, hoàn trả nguyên tử byte-exact từng tệp cấu hình cũ (giữ bản sao lưu nếu tệp đang bị khóa & giữ nguyên launcher cũ chưa chạm tới), gỡ 4 wrapper `.cmd` + 4 POSIX shim (`codex`, `codex-official`, `codex-t3`, `codex-manage`) và chỉ cập nhật `PATH` khi thực sự có mục khớp |
| [`scripts/restore-original.sh`](../scripts/restore-original.sh) | Bash (`set -euo pipefail`, macOS / Linux / WSL) | Công cụ khôi phục chính xác tương đương cho macOS / Linux / WSL (hỗ trợ `--snapshot PATH`, `--dry-run`, `--remove-lane2-home`, preflight kiểm chứng manifest `.rollback/latest.tsv` kể cả `# status=in-progress` + SHA-256 + `original_mode` `000`–`777` & chặn symlink/path traversal/SUID, idempotent) | `~/.codex-official/.rollback/latest.tsv`, các bản `.backup-*` và symlink trong `~/.codex-official` | Tháo an toàn symlink trước, hoàn trả byte-exact từng tệp + đúng quyền POSIX qua staging `mktemp` nguyên tử và chỉ gỡ 4 wrapper (`codex`, `codex-official`, `codex-t3`, `codex-manage`) do bộ kit sinh (không xóa launcher cũ chưa chạm tới) |
| [`scripts/doctor.ps1`](../scripts/doctor.ps1) | PowerShell 5.1+ / 7+ (Windows) | Kiểm tra sức khỏe, tương thích hệ thống, thứ tự `PATH`, 6/6 đích Junction (chuẩn hóa đường dẫn dài 8.3), **chế độ quyền Sandbox 2 CLI (`Ask` / `Config` / `[WARN] Full Access`)**, 7 probe `execpolicy`, quét plaintext secret, kiểm tra NTFS Allow-ACE `CodexSandboxUsers`, kiểm tra tham khảo chỉ-đọc `.sandbox\deny_read_acl_state.json` & kiểm tra chỉ-đọc **Rollback Journal** (**Chỉ đọc — Read-Only**) | `OSVersion`, `Get-Volume`, `Get-Command codex/codex-t3/python`, đích Junction, `default.rules`/`AGENTS.md`/`config.toml`, `Get-Acl`, `.sandbox\deny_read_acl_state.json` *(chỉ đọc trạng thái)*, `.rollback\latest.json` *(chỉ đọc trạng thái)*, `auth.json` *(chỉ đọc `auth_mode` đã lọc)* | **Không ghi bất kỳ tệp nào** |
| [`scripts/doctor.sh`](../scripts/doctor.sh) | Bash (`set -euo pipefail`, macOS / Linux / WSL) | Phiên bản chẩn đoán hệ thống, kiểm tra **chế độ quyền Sandbox 2 CLI (`Ask` / `Config` / `[WARN] Full Access`)**, quyền POSIX `0600`, rò rỉ plaintext `api_key =`, 5 probe thực thi `execpolicy` & kiểm tra chỉ-đọc **Rollback Journal** (`# status=in-progress` / symlink) tương đương cho Unix (**Chỉ đọc — Read-Only**) | `uname`, `df`, `command -v codex/codex-t3/python3`, 6 symlinks, `default.rules`/`AGENTS.md`/`config.toml`, `.rollback/latest.tsv`, quyền POSIX (`stat`), trường `auth_mode` trong `auth.json` | **Không ghi bất kỳ tệp nào** |
| [`scripts/sync-sessions.py`](../scripts/sync-sessions.py) | Python 3.8+ (thư viện chuẩn `sqlite3`, `json`, `os`, `re`, `pathlib`, `tempfile`) | Đồng bộ UPSERT 1 chiều hoặc **2 chiều (`--bidirectional`)** cho phiên, mục đã ghim (`Pinned`) & `Goals` (mở nguồn **chỉ-đọc `?mode=ro` + `PRAGMA query_only=ON`**), hỗ trợ `--source`/`--target` (alias `--lane1`/`--lane2`), sao lưu SQLite trước khi ghi (`--backup-target`), bảo toàn `is_pinned = 1` và không ghi đè `updated_at` mới hơn, cứu hộ tệp cục bộ không ghi đè & từ chối symlink fail-closed (`--rescue-shared-files`), SQL tham số hóa + allowlist bảng/cột & ghi JSONL nguyên tử `0600` (hỗ trợ `--pinned-only`, `--dry-run`) | `<source>/session_index.jsonl`, `<source>/state_*.sqlite` *(read-only URI + `PRAGMA quick_check(1)`)*, `<source>/goals_*.sqlite` *(read-only URI)*, `PRAGMA table_info(...)`, thư mục cục bộ trong `<source>` khi bật `--rescue-shared-files` | `<target>/session_index.jsonl` *(temp `0600` + `fsync` + `os.replace`)*, `<target>/state_*.sqlite`, `<target>/goals_*.sqlite` *(kèm `.sync-backup-*` nếu bật `--backup-target` & `PRAGMA wal_checkpoint(TRUNCATE)`)*; khi bật `--bidirectional` cập nhật an toàn cả 2 chiều |

### 2.2. Tệp mẫu chính sách & phối hợp (`templates/`)

| Tệp | Mục đích & Hành vi thực thi |
| :--- | :--- |
| [`templates/default.rules`](../templates/default.rules) | Bộ luật **Execpolicy (Starlark)** nạp vào tầng Rust của Codex (có chú thích chi tiết từng nhóm lệnh & cách tùy biến an toàn): chặn cứng (`forbidden`) nhóm lệnh phá hệ thống/ransomware (`vssadmin`, `bcdedit`, `wbadmin`, `diskpart`, `format`), cài persistence/Registry (`schtasks`, `sc`, `reg add/delete/import`), phá NTFS ACL/mạng (`icacls`, `takeown`, `net`, `net1`, `netsh`), xóa lịch sử Git (`git push --force/-f`), trình thông dịch corpus & Windows LOLBins để ép phân tích tĩnh (`php`, `ruby`, `perl`, `cscript`, `wscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `msiexec`, `wmic`, `Start-Process`/`start-process`/`saps`, `Invoke-Expression`/`invoke-expression`/`iex`/`IEX`), kèm biến thể `.exe`/`.com`; bắt buộc hỏi xác nhận (`prompt`) với `git push`, `git reset --hard`, `git clean`; và để trống 100% (`matchedRules: []`) cho toàn bộ lệnh duyệt cây thư mục & thao tác file CRUD (`rg`, `find`, `git status`, `Get-ChildItem`, `Remove-Item`, `rm`, `mv`, `cp`, `mkdir`, `apply_patch`). |
| [`templates/AGENTS.lane1.md`](../templates/AGENTS.lane1.md) | Chỉ thị toàn cục cài vào `~/.codex/AGENTS.md` cho **Luồng 1 (Codex Desktop — Tài khoản chính `acc chính`, giữ toàn quyền như trước)**: chống Prompt Injection, **cách ly chỉ phân tích tĩnh (`Static-Analysis-Only` — chỉ cấm thực thi mẫu/payload bên thứ 3)**, cấm đọc/in `config.toml`/`auth.json`/`.rollback/`/`.env`/`.ssh/`, giữ kỷ luật artifact, và khẳng định **Codex Desktop giữ toàn quyền (`toàn quyền như trước`) nắm toàn bộ cây thư mục, đọc/ghi/tạo/sửa/xóa file, build & test trên toàn dự án mặc định (Rule 4 & Rule 6, chỉ chia phân vùng nếu người dùng chủ động khai báo nhiệm vụ song song trong `DUAL_LANE_BRIDGE.md`)**. |
| [`templates/AGENTS.lane2.md`](../templates/AGENTS.lane2.md) | Chỉ thị toàn cục cài vào `~/.codex-official/AGENTS.md` cho **Luồng 2 (Codex CLI — Linh hoạt Login OAuth & API Key / Gateway)**: giữ nguyên chuẩn bảo vệ, **`Static-Analysis-Only`** *(giới hạn nghiêm ngặt vào việc không thực thi mẫu mã độc/payload bên thứ 3, không bao giờ chặn phát triển dự án)*, luật **Zero-Collision** (không sửa vùng tệp/catalog của Luồng 1, dùng `CARGO_TARGET_DIR` riêng, đọc chéo handoff của Luồng 1), đồng thời khẳng định **đầy đủ năng lực bản Codex CLI gốc gọn trong thư mục dự án** (coding, refactor, build, test, debug, duyệt cây thư mục, File CRUD, MCP/skills/memories/goals), **tham khảo thuật toán/tài liệu bên ngoài ở chế độ chỉ-đọc (read-only)** và tóm tắt **3 chế độ quyền CLI** (`Xin yêu cầu` / `Thuộc cấu hình config.toml` / `Toàn quyền`). |
| [`templates/DUAL_LANE_BRIDGE.md`](../templates/DUAL_LANE_BRIDGE.md) | Tệp cầu nối mẫu để chép vào dự án của bạn (`artifacts/dual-lane/DUAL_LANE_BRIDGE.md`), phân định rõ vai trò Luồng 1 (Desktop `acc chính`) vs. Luồng 2 (CLI Login & API Key), toàn quyền nắm cây thư mục & File CRUD trong vùng sở hữu, quy tắc an toàn bắt buộc giữ nguyên, và lưu ý ranh giới mềm vs. cứng (`-UseGitWorktree` / `--use-git-worktree`). |

### 2.3. Tài liệu & cấu hình repo (`docs/`, gốc repo)

| Tệp | Nội dung |
| :--- | :--- |
| [`README.md`](../README.md) | Trang tổng quan, bảng chọn kịch bản theo nhu cầu, ranh giới bảo mật minh bạch, sơ đồ kiến trúc và lệnh cài nhanh 3 bước. |
| [`docs/GUIDE_AND_MANIFEST.md`](./GUIDE_AND_MANIFEST.md) | Chính tài liệu bạn đang đọc — khai báo chi tiết mã nguồn, hàm, bảng tham số đầy đủ và hướng dẫn gỡ bỏ an toàn. |
| [`docs/REAL_CODEX_CHECKLIST.md`](./REAL_CODEX_CHECKLIST.md) | Danh sách lệnh kiểm chứng thực nghiệm trước & sau khi cài đặt (0 plaintext key, behavioral `execpolicy check`, kiểm tra ACL/chmod, merge TOML, UPSERT SQLite và rollback `-DryRun`). |
| [`docs/SECURITY_MODEL.md`](./SECURITY_MODEL.md) | Phân tích sâu 4 lớp phòng thủ, bảng minh bạch Bộ Kit vs. Giới hạn OS/Codex runtime (bao gồm kế thừa `CodexSandboxUsers`, atomic replace reset DACL, `keyring` + `env_key`), ranh giới Mềm vs. Cứng và Khiên Git. |
| [`docs/TROUBLESHOOTING.md`](./TROUBLESHOOTING.md) | Hướng dẫn khắc phục các lỗi thực chiến thường gặp (bao gồm cảnh báo Defender trên `.jsonl`, reset `kernel_acl` sau `codex features`, phục hồi cài đặt bị ngắt giữa chừng, lỗi worktree fail-closed, đồng bộ 2 chiều, kiểm tra API Key/tài khoản qua `codex-manage` và gỡ Sandbox 2 bảo toàn 100% lịch sử chat). |
| [`tests/test_sync_sessions.py`](../tests/test_sync_sessions.py) | Bộ Unit Test Python (`unittest`) kiểm chứng đọc nguồn `?mode=ro`, UPSERT (`INSERT` + `UPDATE`), atomic JSONL, `--pinned-only`, `--bidirectional` hợp nhất 2 chiều, bảo toàn `updated_at` & `is_pinned = 1`, `--backup-target`, `--rescue-shared-files` (không ghi đè file gốc & từ chối symlink fail-closed), lệch schema, path-traversal/symlink và `--dry-run`. |
| [`tests/test-kit.ps1`](../tests/test-kit.ps1) | Bộ Test PowerShell **13 pha** kiểm chứng AST/CRLF/BOM (kể cả `codex-manager.ps1`), `-DryRun`/`-WhatIf`, merge `config.toml` & `[features]` không phá hủy, cô lập `env_key` & `-GatewayTargetLane` / `-ConfigureCliGateway` (Luồng 2 CLI vừa hỗ trợ Login vừa hỗ trợ API Key), kế thừa chỉ-đọc `[projects."..."]` từ Desktop mà giữ SHA-256 của `~/.codex/config.toml` nguyên vẹn 100% kèm **bảo toàn nghiêm ngặt `trust_level`** & `-TrustRepoPath` opt-in, cảnh báo opt-in `-ShareAuthToLane2`, đường dẫn tương đối `-RepoPath .`, 4 POSIX shim không đuôi cho Git Bash/MSYS2 (`codex`, `codex-official`, `codex-t3`, `codex-manage`), UTF-8 không BOM, khóa ACL 2 bước & `-ReapplyAclOnly`, chuẩn hóa đường dẫn ngắn 8.3 (`RUNNER~1`), worktree fail-closed cứng, `doctor.ps1`, chống path-traversal, khôi phục SHA-256, khôi phục cài đặt bị ngắt giữa chừng, vòng lặp 3x install/rollback, bảo toàn link có trước (`SharedLinkRecords`), khôi phục đúng thư mục backup, preflight fail-closed khi thiếu backup, và **Pha 13 (13a–13g) kiểm thử toàn diện `codex-manager.ps1` & 3 chế độ quyền CLI** (`ApiGpt`, `ApiOther`, `Login`, `CheckApiKey` offline + loopback HTTP mock `200`/`401`/HTTPS-only/no-redirect không lộ key, `CheckAccounts` chỉ-đọc, `SyncHistory` 2 chiều, `RemoveSandbox2` cứu hộ 100% lịch sử về GPT 1 trước khi xóa, và **Pha 13g** kiểm chứng `SetCliMode` + `setup-dual-lane.ps1 -CliMode` cho cả 3 chế độ `Ask`/`Config`/`FullAccess` fail-closed). |
| [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | Pipeline GitHub Actions CI 4 job (`hygiene-and-policy`, Windows PS 5.1 & 7+ 13 pha, Ubuntu, macOS) tự động chạy kiểm tra cú pháp (`bash -n` cả 4 `.sh` kể cả `codex-manager.sh`), CRLF/LF/BOM (`codex-manager.ps1` + `.sh`), unit test Python, smoke test fail-closed worktree, bảo toàn `trust_level` (Section 9e–9f), cảnh báo `--share-auth-to-lane2`, **Section 10 (10a–10h) kiểm thử toàn diện 7 tác vụ `codex-manager.sh` & 3 chế độ quyền CLI (`--cli-mode` / `set-cli-mode`)**, quét rò rỉ bí mật, khôi phục cài đặt bị ngắt và vòng lặp 3x install/rollback **bằng binary `codex` giả lập (`mock codex`) & local loopback mock** — **không thay thế** chạy `doctor.ps1` / `doctor.sh` và kiểm chứng trực tiếp trên bản Codex Desktop/CLI thật trên máy của bạn. |
| [`.gitattributes`](../.gitattributes) | Khóa định dạng xuống dòng (`eol=lf` cho `.sh`/`.py`/`.md`/`.rules`/`LICENSE`/`NOTICE`, `eol=crlf` cho `.ps1`/`.cmd`). |
| [`.gitignore`](../.gitignore) | Chặn tuyệt đối không commit `.env`, `config.toml`, `*.backup-*`, `auth.json`, `*.sqlite`, `.rollback/`, `scripts/__pycache__/`, `__pycache__/`, `*.pyc`. |
| [`LICENSE`](../LICENSE) | Giấy phép mã nguồn mở **Apache License 2.0**. |
| [`NOTICE`](../NOTICE) | Thông báo bản quyền chuẩn Apache-2.0 (`Copyright 2026 Lê Hoàng Ngọc Tươi`). |
| [`SECURITY.md`](../SECURITY.md) | Chính sách bảo mật, ranh giới trung thực & quy trình báo cáo lỗ hổng riêng tư hiển thị trên tab **Security** của GitHub. |

---

## 3. Diễn giải chi tiết luồng thực thi & các hàm chính

### 3.1. Luồng chạy của `scripts/setup-dual-lane.ps1`

1. **Dò tệp thực thi Codex (`Resolve-CodexExecutable`):** Thứ tự ưu tiên `-CodexPath` $\rightarrow$ `WindowsApps` (`OpenAI.Codex`) $\rightarrow$ `PATH` *(loại trừ `~/.local/bin` tránh vòng lặp đệ quy)* $\rightarrow$ `%APPDATA%\npm\codex.cmd` và `%LOCALAPPDATA%\Programs\Codex\codex.exe`. Dừng sớm (fail-closed) nếu không tìm thấy.
2. **Kiểm tra ổ đĩa & NTFS (`Get-Volume`):** Xác nhận ổ chứa `-Lane2Home` dùng **NTFS** (điều kiện bắt buộc của NTFS Directory Junction) và kiểm tra dung lượng trống thực tế của ổ chứa `-CargoTargetDir` (cảnh báo nếu dưới `10 GB`).
3. **Dò thật Feature Flags (`Get-SupportedCodexFeatures`):** Chạy `& $CodexExe features list` trong `CODEX_HOME` tạm rồi dọn sạch trong khối `finally`.
4. ***(Tùy chọn `-UseGitWorktree`)* Tạo Git Worktree riêng cho Luồng 2:** Khởi tạo worktree độc lập (`<RepoPath>-lane2`, nhánh `-Lane2Branch`) để cưỡng chế phân vùng ghi ở tầng OS Sandbox.
5. **Chuẩn bị thư mục & khởi tạo nhật ký rollback tăng dần:** Tạo `~/.codex`, `~/.codex/rules`, `~/.codex-official`, `~/.codex-official/rules`, `~/.local/bin`, `~/.codex-official/.rollback` và ghi ngay checkpoint khởi tạo `latest.json` (`Completed: false`, khóa ACL tức thì) trước khi thực hiện bất kỳ thao tác ghi hay tạo Junction nào (bỏ qua khi `-DryRun`/`-WhatIf`).
6. **Tạo 6 NTFS Directory Junction:** Nối `memories`, `memories_v2`, `sessions`, `archived_sessions`, `skills`, `plugins` từ `~/.codex-official` sang `~/.codex` (giữ nguyên nếu đã là Junction; sao lưu thư mục cũ trước khi tạo nếu có xung đột), và ghi checkpoint nhật ký rollback sau từng Junction.
7. **Cài đặt tường lửa lệnh (`rules/default.rules`):** Sao lưu bản cũ kèm SHA-256, ghi checkpoint trước khi ghi đè rồi cài vào cả 2 luồng.
8. **Cài đặt `AGENTS.md` toàn cục:** Sao lưu bản cũ, ghi checkpoint rồi cài `AGENTS.lane1.md` vào `~/.codex/AGENTS.md`, `AGENTS.lane2.md` vào `~/.codex-official/AGENTS.md`.
9. **Kế thừa Chỉ-đọc `[projects.*]` (Bảo toàn Nghiêm ngặt `trust_level` & `-TrustRepoPath` Opt-In — v1.4), Merge Không Phá Hủy `[features]` & 3 Chế độ Quyền `-CliMode` cho `~/.codex-official/config.toml` (Luồng 2 Codex CLI):** Đọc **chỉ-đọc (`read-only`)** `~/.codex/config.toml` (nếu có) và phân tích đúng giá trị `trust_level` của từng mục `[projects."..."]` trên cả Luồng 2 & Luồng 1 (không chạm 1 byte nào vào `~/.codex/config.toml`, chuẩn hóa đường dẫn dài 8.3 chống trùng lặp): chỉ ghi `trust_level = "trusted"` cho các dự án thực sự mang `trust_level = "trusted"`, **bảo toàn nguyên vẹn `trust_level = "untrusted"`**, không nâng cấp mục thiếu `trust_level`, và không tự nâng `-RepoPath` trừ khi truyền `-TrustRepoPath`. **Merge không phá hủy bảng `[features]` và `web_search`** của người dùng (giữ nguyên `multi_agent_v2`, `plugins`, `hooks`, `fast_mode`, `apps`, `browser_use`, v.v., bật các tính năng gốc hỗ trợ như `memories`, `goals`, `image_generation`, `api_key_model_discovery`, không hardcode cờ đã bỏ như `js_repl = false`), giữ nguyên `[mcp_servers.*]`, `[tui]`, `[plugins.*]`, escape chuỗi TOML, áp dụng **`-CliMode`** (`Ask` mặc định: `sandbox_mode = "workspace-write"` + `approval_policy = "on-request"`; `Config`: giữ nguyên `approval_policy` & `sandbox_mode` hiện có trong `config.toml`; `FullAccess`: hiển thị cảnh báo nguy hiểm đỏ/vàng & từ chối fail-closed `exit 1` nếu thiếu `-ConfirmFullAccess` hoặc gõ đúng `TOAN QUYEN`/`I UNDERSTAND`, khi xác nhận ghi `approval_policy = "never"` + `sandbox_mode = "danger-full-access"`), đặt `network_access = false` (trừ khi bật `-AllowSandboxNetwork` hoặc giữ nguyên trong `Config`), `daemon_auto_start = false` (khi hỗ trợ), lọc biến môi trường nhạy cảm, tách `CARGO_TARGET_DIR`, khóa ACL và ghi checkpoint. Nếu chủ động bật cờ opt-in **`-ShareAuthToLane2`** (alias `-ShareOfficialAuth`, **tắt mặc định**), sao chép nguyên tử `~/.codex/auth.json` sang `~/.codex-official/auth.json` kèm sao lưu rollback, khóa ACL 2 bước (giữ `~/.codex/auth.json` nguyên vẹn 100%) và in cảnh báo `[WARN]` rõ ràng (cảnh báo mức cao hơn nếu đi cùng cổng API bên thứ 3 — nên tránh/thận trọng vì tạo bản sao thứ 2 của `auth.json` trong Luồng 2).
10. ***(Tùy chọn `-ConfigureCliGateway` hoặc `-ConfigureGateway` + `-GatewayTargetLane Lane1|Lane2|Both`)* Cấu hình API Key / cổng Gateway linh hoạt (giữ Codex Desktop toàn quyền như trước):** Mặc định (và khi truyền `-ConfigureCliGateway` hoặc `-GatewayTargetLane Lane2`), tệp `~/.codex/config.toml` của **Codex Desktop (Luồng 1 — Tài khoản chính `acc chính`) không bị chỉnh sửa 1 byte nào**, giữ nguyên 100% quyền hạn, cấu hình và mạng gốc của Desktop; ngay cả khi truyền `-GatewayTargetLane Lane1` hoặc `Both`, bộ kit chỉ merge không phá hủy cấu hình provider (`env_key`) và **không bao giờ ép `sandbox_mode` hạn chế hay `network_access = false` vào `~/.codex/config.toml`**. Trên Luồng 2 (`~/.codex-official`, Codex CLI), `-ConfigureCliGateway` (hoặc `-GatewayTargetLane Lane2` / `Both`) cho phép CLI dùng song song hoặc linh hoạt cả **API Key / Gateway (`env_key` qua `-CliApiKeyEnv` / `-GatewayApiKeyEnv`) lẫn Đăng nhập OAuth (`codex login` / `-ShareAuthToLane2`)**. Khuyến nghị nhập key ẩn qua `-PromptGatewayApiKey` hoặc đặt trước biến môi trường `-CliApiKeyEnv` (**không bao giờ ghi plaintext key** vào `config.toml` hay `.backup-*`). Lưu bản sạch `~/.codex/config.backup.toml` khi sửa Luồng 1 (đồng thời theo dõi `ExistedPrior = false` trong manifest để rollback không để lại tệp rác).
11. **Sao lưu launcher cũ (nếu có) & tạo bộ 4 launcher đa Shell (`.cmd` + POSIX shim không đuôi) trong `~/.local/bin/`:** Từng launcher (`codex.cmd`, `codex-official.cmd`, `codex-t3.cmd`, `codex-manage.cmd` cùng 4 POSIX shim không đuôi chuẩn LF `codex`, `codex-official`, `codex-t3`, `codex-manage` cho Git Bash / MSYS2) được sao lưu, ghi và checkpoint riêng lẻ (nếu cài đặt bị ngắt giữa Bước 11, các launcher chưa chạm tới vẫn còn nguyên). Sinh wrapper mới (escape `%` bằng `Escape-CmdSetValue`, tự thêm `chcp 65001 >nul` khi đường dẫn có Unicode, tự dò lại gói `WindowsApps`). Khi bật `-UseGitWorktree`, wrapper Luồng 2 áp dụng **Hard Fail-Closed Worktree Isolation**: so khớp cả đường dẫn dài chuẩn lẫn tên ngắn 8.3 (`%%~fs`), tự chuyển `cwd` từ repo gốc lẫn **mọi thư mục con** sang worktree Luồng 2, hậu kiểm `cwd` sau `cd`, **từ chối chạy (`exit 1`)** nếu worktree thiếu/bị xóa/lỗi `cd` (tắt auto-cd chỉ bằng `CODEX_NO_AUTO_WORKTREE_CD=1`), và Guard 2 luôn chặn `-C`/`-C=`/`-C<path>`/`-C"<path>"`/`--cd`/`--cd=`/`--add-dir`/`--add-dir=` trỏ về repo chính. Đồng thời đưa `~/.local/bin` lên đầu User `PATH` (trừ khi truyền `-SkipPathUpdate`). *(Cờ `-ReapplyAclOnly` cho phép khóa nhanh lại ACL trong ~1 giây sau khi Codex cập nhật cấu hình.)*
12. ***(Tùy chọn `-InstallBridgeTemplate`)* Chép mẫu `DUAL_LANE_BRIDGE.md`:** Tạo `<RepoPath>\artifacts\dual-lane\DUAL_LANE_BRIDGE.md` nếu chưa tồn tại (không ghi đè tệp đã có).
13. **Hoàn tất Manifest SHA-256 (`Completed = true`), khóa ACL 2 bước & *(Tùy chọn `-SyncSessions`)* Đồng bộ phiên:** Đánh dấu hoàn tất `~/.codex-official/.rollback/latest.json` + `snapshot-<timestamp>.json`, chạy lượt quét cuối `Protect-SensitiveFileAcl` lên `auth.json`, `config.toml`, bản sao lưu và manifest rollback, chạy `scripts/sync-sessions.py` (nếu bật `-SyncSessions` và có Python 3 thật), sau đó kiểm chứng `codex.cmd --version`.

### 3.2. Bản đồ Chi tiết Các Hàm Chính

#### `scripts/setup-dual-lane.ps1` (PowerShell 5.1+ / 7+)
| Tên hàm | Đầu vào | Thực hiện chính xác điều gì |
| :--- | :--- | :--- |
| `Write-Step` | `Message` | In tiêu đề từng bước cài đặt có màu sắc rõ ràng trên Console. |
| `Resolve-CanonicalLongPath` | `PathValue` | Chuẩn hóa đường dẫn Windows (kể cả tên ngắn 8.3 như `RUNNER~1`, `PROGRA~1` và nhánh lá chưa tồn tại) về đường dẫn dài chuẩn bằng Win32 `GetLongPathNameW` mà **không** giải tham chiếu NTFS Junction/symlink. |
| `Save-RollbackManifestCheckpoint` | `Stage`, `Completed` | Ghi nguyên tử nhật ký rollback tăng dần (`latest.json` và `snapshot-<stamp>[-N].json` UTF-8 không BOM + khóa ACL tức thì) sau từng bước thay đổi (`Completed: false` trong khi cài $\rightarrow$ `true` ở Bước 13) để cài đặt bị ngắt giữa chừng luôn phục hồi được. |
| `Escape-TomlBasicString` | `Value` | Escape ký tự `\`, `"` và ký tự điều khiển thành chuỗi TOML hợp lệ (an toàn với đường dẫn có dấu cách, Unicode, `&`). |
| `Escape-CmdSetValue` | `Value`, `Label` | Xác thực chống ký tự điều khiển và escape `%` $\rightarrow$ `%%` cho `set "..."` trong `.cmd` wrapper (an toàn với đường dẫn chứa `100%`, `&`, `!`, dấu cách và Unicode). |
| `Write-Utf8NoBom` | `FilePath`, `Text` | Ghi tệp `config.toml`, `.cmd` và manifest JSON theo chuẩn **UTF-8 không BOM** bằng cơ chế **nguyên tử** (ghi tệp tạm cùng thư mục rồi `File.Replace`/`Move`) để tránh hỏng tệp khi bị ngắt giữa chừng. |
| `Assert-NoPlaintextSecretInToml` | `TomlContent`, `ContextLabel`, `ForbiddenLiteralSecret` | Cổng chặn fail-closed trước khi ghi `config.toml`: từ chối ghi đĩa nếu phát hiện `experimental_bearer_token`, plaintext `api_key`, hoặc chuỗi secret vừa nhập. |
| `Assert-SafeGitBranchName` | `BranchName` | Xác thực tên nhánh `-Lane2Branch` chống tiêm tham số Git (`-`) và ký tự cấm trước khi Bước 4 gọi `git check-ref-format` và tạo worktree. |
| `Protect-SensitiveFileAcl` | `FilePath` | Từ chối reparse point, chạy **2 lệnh `icacls.exe` tuần tự**: (1) `icacls <file> /inheritance:d` để tắt kế thừa từ `~/.codex*` và chuyển ACE kế thừa thành tường minh, rồi kiểm tra sự tồn tại của `CodexSandboxUsers` qua `NTAccount.Translate` + `Get-Acl` và chỉ chạy (2) `icacls <file> /remove:g "CodexSandboxUsers"` khi nhóm có mặt (bỏ qua êm ái trên máy mới chưa có nhóm này, không đụng tới Deny ACE bảo vệ). *(Lưu ý: atomic replace của Codex khi sửa `config.toml`/`auth.json` sẽ reset DACL — xem [SECURITY_MODEL.md](SECURITY_MODEL.md)).* |
| `Backup-IfExists` | `FilePath` | Tính mã băm SHA-256 bản gốc, sao lưu sang `<FilePath>.backup-yyyyMMdd-HHmmss`, khóa ACL bản sao lưu và ghi nhận vào manifest rollback (tôn trọng `-DryRun` / `-WhatIf`). |
| `Resolve-CodexExecutable` | `ExplicitPath`, `ExcludedDir` | Tự dò đường dẫn thật của `codex.exe`/`codex.cmd` theo 4 nguồn: `-CodexPath` $\rightarrow$ `WindowsApps` (`OpenAI.Codex`) $\rightarrow$ `PATH` *(loại trừ `~/.local/bin`)* $\rightarrow$ `%APPDATA%\npm` & `%LOCALAPPDATA%\Programs`. |
| `Get-SupportedCodexFeatures` | `ExePath`, `ProbeHome` | Chạy `& $ExePath features list` trong `CODEX_HOME` tạm cô lập để lấy danh sách feature flags thật mà bản Codex trên máy hỗ trợ. |
| `Get-ExistingTrustedProjects` | `ConfigPaths[]` | Quét các `config.toml` cũ của cả Luồng 2 & Luồng 1 (đọc tường minh `-Encoding UTF8`, chặn reparse point) và kiểm tra giá trị `trust_level` thực tế của từng `[projects.'...']` / `[projects."..."]` (v1.3.3): chỉ trả về `"trusted"` cho mục thật sự mang `trust_level = "trusted"`, bảo toàn nguyên vẹn `trust_level = "untrusted"`, và không bao giờ nâng cấp mục thiếu `trust_level` lên `"trusted"`. |
| `Merge-CodexConfigToml` | `ExistingPath`, `ManagedTopBlock`, `ManagedSectionsBlock`, `ManagedTopKeys[]`, `ManagedSectionNames[]` | Hợp nhất không phá hủy vào `config.toml` hiện có: giữ nguyên mọi khóa top-level (kể cả mảng/bảng nhiều dòng), comment `#` sau header section, `[[array_of_tables]]` và section tùy chỉnh (`[mcp_servers.*]`, `[tui]`, `[plugins.*]`), loại bỏ `experimental_bearer_token` cũ và chỉ cập nhật phần do Dual-Lane quản lý. |

#### `scripts/doctor.ps1` (PowerShell 5.1+ / 7+ — Chỉ đọc)
| Thành phần / Mục kiểm tra | Thực hiện chính xác điều gì |
| :--- | :--- |
| `Report` | Định dạng và thống kê 3 trạng thái `[PASS]` / `[WARN]` / `[FAIL]`; thoát mã `1` nếu có `[FAIL]` (vd ổ không phải NTFS, phát hiện plaintext secret trong `config.toml`, hoặc lệnh bắt buộc cấm lại bị `execpolicy` cho phép), mã `0` nếu không có `[FAIL]`. |
| 10 nhóm kiểm tra thật (Read-Only) | (1) OS & PowerShell; (2) Toàn bộ ổ đĩa cố định, NTFS & dung lượng trống thật; (3) Thứ tự `PATH` & phiên bản `codex` / `codex-t3`; (4) Tình trạng & đích trỏ thật của 6/6 NTFS Directory Junction (chuẩn hóa đường dẫn dài 8.3); (5) **Chế độ quyền Sandbox 2 CLI (`Sandbox 2 CLI Mode`)**: báo `[PASS]` cho `Ask` (`on-request` + `workspace-write`) hoặc `Config` tùy chỉnh, và báo **`[WARN]`** *(không phải `[FAIL]`)* khi `sandbox_mode = "danger-full-access"` đang bật chủ đích; (6) Đầy đủ `config.toml` + `default.rules` + `AGENTS.md`, trạng thái `Static-Analysis-Only`, `sandbox_net=restricted/enabled`, `[shell_environment_policy]` & **7 live probe `codex execpolicy check`** (`php`, `mshta`, `vssadmin`, `icacls`, `git push --force`, `Start-Process`, `iex`); (7) Quét `config.toml` trong bộ nhớ chống plaintext `experimental_bearer_token` / `api_key` *(tuyệt đối không in giá trị secret)*; (8) Cách ly `auth.json` *(chỉ đọc `auth_mode` đã lọc theo allowlist)*, kiểm tra **Allow ACE** của `CodexSandboxUsers` + `AreAccessRulesProtected`, và kiểm tra tham khảo chỉ-đọc `.sandbox\deny_read_acl_state.json`; (9) Trạng thái **Rollback Journal** (`.rollback\latest.json` — báo `[WARN]` nếu `Completed=false` do cài đặt bị ngắt giữa chừng hoặc bị thay bằng reparse point); (10) Tình trạng Python 3 thật cho `sync-sessions.py`. |

#### `scripts/sync-sessions.py` (Python 3.8+ — Chỉ dùng thư viện chuẩn)
| Tên hàm | Đầu vào | Thực hiện chính xác điều gì |
| :--- | :--- | :--- |
| `connect_readonly` | `db_path`, `timeout` | Mở tệp SQLite nguồn của Luồng 1 (và DB đích khi `--dry-run`) ở chế độ chỉ-đọc (`file:...?mode=ro` + `PRAGMA query_only=ON`, `PRAGMA busy_timeout`) để tuyệt đối không chiếm khóa ghi khi Luồng 1 đang chạy. |
| `ensure_contained_path` | `base_dir`, `candidate` | Chặn path-traversal (`..`) và symlink trỏ ra ngoài thư mục Codex gốc (bao gồm cả tệp sidecar `-wal`/`-shm`/`-journal`). |
| `find_latest_versioned_db` | `directory`, `prefix` | Tự dò tệp SQLite phiên bản mới nhất (`state_*.sqlite`, `goals_*.sqlite`) bằng `os.scandir` (an toàn với đường dẫn chứa ký tự `[` `]`). |
| `get_tables` / `get_columns` / `get_column_info` | `conn`, `table` | Kiểm tra allowlist bảng (`ALLOWED_TABLES`), xác thực tên cột (`validate_sql_identifier`/`quote_identifier`), truy vấn `sqlite_master` và `PRAGMA table_info(...)` để tương thích động mọi phiên bản schema và chặn second-order SQLi. |
| `sync_session_index` / `atomic_write_text` | `lane1`, `lane2`, `dry_run`, `allowed_ids` | Hợp nhất không trùng lặp các bản ghi theo `id` giữa 2 tệp `session_index.jsonl` (hỗ trợ `--pinned-only`), ghi nguyên tử qua `NamedTemporaryFile` + `0o600` (POSIX) + `fsync` + `os.replace`. |
| `copy_shared_table` | `c1`, `c2`, `table`, `dry_run` | Chỉ sao chép phần giao các cột tồn tại ở cả 2 DB (`INSERT OR REPLACE`) bằng SQL tham số hóa (`?`), tránh lỗi lệch schema. |
| `sync_state_db` | `source`, `target`, `repo_path`, `approval_mode`, `pinned_only`, `dry_run`, `backup_target` | Kiểm tra toàn vẹn nguồn (`PRAGMA quick_check(1)`), tùy chọn tạo bản sao lưu SQLite (`<db>.sync-backup-<timestamp>` qua online `.backup()` khi bật `--backup-target`), nạp dữ liệu trước khi mở transaction ghi (`BEGIN IMMEDIATE`), thực hiện **UPSERT bảo toàn xung đột** cho `threads` cùng `thread_sections`, `projects`, `project_roots` (**giữ nguyên `is_pinned = 1` nếu một trong hai bên đã ghim** và **không bao giờ ghi đè metadata `updated_at` mới hơn của đích bằng dòng cũ hơn**), tự xử lý an toàn khi DB bị khóa/hỏng mà không làm hư DB đích, và chạy `PRAGMA wal_checkpoint(TRUNCATE)`. |
| `sync_goals_db` | `source`, `target`, `dry_run`, `backup_target` | Đồng bộ bảng `thread_goals` và `thread_goal_continuation_deferrals` (kèm tùy chọn `--backup-target` và `PRAGMA wal_checkpoint(TRUNCATE)`). |
| `--bidirectional` & `--rescue-shared-files` *(v1.4.0)* | `source`, `target`, `dry_run`, `backup_target` | `--bidirectional` chạy đồng bộ 2 chiều (`source -> target` rồi `target -> source`) để GPT 1 và Sandbox 2 hội tụ thành hợp đầy đủ không mất dữ liệu mới hơn của GPT 1; `--rescue-shared-files` duyệt 4 thư mục dùng chung (`sessions`, `archived_sessions`, `memories`, `memories_v2`) trong `--source`: bỏ qua an toàn nếu đã là Junction/symlink (dữ liệu đã ở GPT 1), còn nếu là thư mục cục bộ thật thì sao chép **không ghi đè** các tệp thường còn thiếu sang `--target` và **từ chối mọi symlink fail-closed** (chỉ in basename & số đếm nguyên, 0 rò rỉ nội dung/secret). |

#### `scripts/codex-manager.ps1` (Windows) & `scripts/codex-manager.sh` (macOS / Linux / WSL) — Trung tâm Điều khiển Sandbox 2 (`codex-manage`, v1.4)
| Tác vụ (`-Action` / `--action`) | Cơ chế thực thi & Đảm bảo An toàn |
| :--- | :--- |
| `Menu` / `menu` *(mặc định)* | Hiển thị chế độ quyền Sandbox 2 đang bật ở đầu menu và danh sách tương tác Song ngữ Việt/Anh đầy đủ 7 chức năng (`[1A]`/`[1B]`/`[2]`/`[3]`/`[4]`/`[5]`/`[6]`/`[7]`), điều phối mọi thao tác chỉ bằng phím số. |
| `ApiGpt` / `api-gpt` | Thu nhận **đúng 1 API key ẩn** (`Read-Host -AsSecureString` / `read -rs`, `-ApiKeySecure`, hoặc stdin `-ApiKeyFromStdin`/`--api-key-from-stdin` — **không bao giờ nhận plaintext key trên CLI argv**); sao lưu `~/.codex-official/config.toml`, dọn `model_provider` bên thứ 3 xung đột mà giữ nguyên `[projects.*]` đúng `trust_level`, truyền key qua stdin tới `codex login --with-api-key`, khóa NTFS DACL 2 bước / `chmod 600` lên `auth.json` & `config.toml`, rồi tự đồng bộ lịch sử chat 2 chiều với GPT 1. |
| `ApiOther` / `api-other` | Tạo backup có dấu thời gian của `~/.codex-official/config.toml`, in đường dẫn đầy đủ + mẫu `env_key` an toàn, mở thẳng `config.toml` bằng `-Editor`/`$env:EDITOR`/`notepad.exe` (Windows) hoặc `--editor`/`${VISUAL:-${EDITOR:-vi}}` (Unix); sau khi chỉnh xong: xác thực cú pháp TOML (`tomllib`), cảnh báo nổi bật nếu phát hiện plaintext `api_key` / `experimental_bearer_token`, khóa lại NTFS DACL 2 bước / `chmod 600`, và chạy đồng bộ lịch sử chat 2 chiều. |
| `Login` / `login` | Phát hiện và hỏi dọn `model_provider` bên thứ 3 xung đột (có backup), chạy trực tiếp `CODEX_HOME=<Lane2Home> codex login` (hỗ trợ `-DeviceAuth` / `--device-auth`), khóa NTFS DACL 2 bước / `chmod 600` lên `auth.json`, và chạy đồng bộ lịch sử chat 2 chiều với GPT 1. |
| `CheckApiKey` / `check-api-key` | Kiểm tra **chỉ-đọc** các nguồn API key trên Sandbox 2 (`env_key` + biến môi trường, `OPENAI_API_KEY`, `auth.json`), chỉ in chuỗi mask an toàn (`sk-...xxxx (len=N)` — tuyệt đối không in plaintext), kiểm tra cảnh báo plaintext trong `config.toml` và quyền ACL / `0600`. Khi truyền `-OnlineCheck` / `--online-check` (hoặc chọn `[Y]` trong menu), gửi `GET <base_url>/models` **chỉ qua HTTPS** (loopback HTTP cho test) và **tắt tự động redirect** qua bộ nhớ tiến trình (không lộ trên `ps`/`curl` argv) và báo `VALID (HTTP 200, N models)`, `INVALID/EXPIRED (HTTP 401/403)`, `QUOTA/RATE_LIMITED (HTTP 429)`, `REFUSED`, `REDIRECT_BLOCKED` hoặc `NETWORK_ERROR`. |
| `CheckAccounts` / `check-accounts` | Kiểm tra **chỉ-đọc 100%** cả **GPT 1 (`~/.codex`, Desktop)** và **Sandbox 2 (`~/.codex-official`, CLI)**: chạy `codex login status` (lọc token), đọc metadata an toàn (`auth_mode`, `model_provider`, `env_key`, `approval_policy`, `sandbox_mode`, chế độ quyền CLI đang bật), trạng thái 6 liên kết dùng chung, số phiên (`session_index.jsonl`) và quyền NTFS DACL / `0600` — tuyệt đối không in `access_token`/`refresh_token`/`id_token`/raw key và không sửa 1 byte nào ở GPT 1. |
| `SyncHistory` / `sync-history` | Gọi `scripts/sync-sessions.py --source <Lane1Home> --target <Lane2Home> --bidirectional --backup-target` (tôn trọng `-DryRun` / `--dry-run`). |
| `RemoveSandbox2` / `remove-sandbox2` | **Xóa Sandbox 2 bảo toàn 100% lịch sử chat về GPT 1:** Hỏi xác nhận (trừ khi `-Force`/`--force` hoặc `-DryRun`/`--dry-run`) $\rightarrow$ **Bước 1 (Bắt buộc, fail-closed):** chạy `sync-sessions.py --source <Lane2Home> --target <Lane1Home> --rescue-shared-files --backup-target` để cứu hộ toàn bộ phiên chat, `Pinned`, `Goals` và tệp rollout/memory cục bộ về GPT 1 trước (dừng ngay nếu lỗi) $\rightarrow$ **Bước 2:** gọi `restore-original.* -RemoveLane2Home` / `--remove-lane2-home` tháo sạch liên kết trước rồi xóa `~/.codex-official` và 4 wrapper CLI $\rightarrow$ **Bước 3:** xác minh lịch sử chat của GPT 1 còn nguyên vẹn 100%. |
| `SetCliMode` / `set-cli-mode` | **Chọn 3 chế độ quyền Sandbox 2 (`-CliMode` / `--cli-mode`):** `[1] Xin yêu cầu` (`Ask`/`ask`: `on-request` + `workspace-write`, gọn trong thư mục dự án, tham khảo bên ngoài chỉ-đọc), `[2] Thuộc cấu hình config.toml` (`Config`/`config`: tôn trọng nguyên vẹn `approval_policy` & `sandbox_mode` trong `config.toml`, tùy chọn mở chỉnh + kiểm tra TOML), và `[3] Toàn quyền` (`FullAccess`/`full-access` — DANGER: `never` + `danger-full-access`, **bắt buộc hiển thị khung cảnh báo nguy hiểm đỏ/vàng như bản Codex thật & xác nhận tường minh** bằng cách gõ `TOAN QUYEN`/`I UNDERSTAND` khi tương tác hoặc cờ `-ConfirmFullAccess`/`--confirm-full-access` khi không tương tác; `-Force`/`--force` một mình không thể vượt qua; **từ chối fail-closed `exit 1` và giữ `config.toml` `0` thay đổi nếu không xác nhận**). Luôn tạo backup, bảo toàn `[projects.*]` theo `trust_level` cùng `[features]`/`[mcp_servers.*]`/`[plugins.*]`, khóa ACL 2 bước / `chmod 600` và đồng bộ lịch sử chat 2 chiều. |

#### `scripts/setup-dual-lane.sh`, `scripts/doctor.sh`, `scripts/restore-original.sh` (Bash — macOS / Linux / WSL)
* `setup-dual-lane.sh`: Chạy với `set -euo pipefail`, `umask 077`, `chmod 700` trên thư mục Codex/`.rollback` và `chmod 600` trên `config.toml`/`auth.json`/bản sao lưu nội bộ, ghi tệp nguyên tử qua `mktemp` + `trap` dọn tệp tạm (hỗ trợ `INT`/`TERM`), từ chối ghi đè symlink, kế thừa chỉ-đọc `[projects.*]` từ Luồng 1 sang Luồng 2 với **bảo toàn nghiêm ngặt `trust_level`** & `--trust-repo-path` opt-in, phát `[WARN]` rõ ràng khi bật cờ opt-in `--share-auth-to-lane2`, hỗ trợ **`--cli-mode ask|config|full-access`** (`CODEX_CLI_MODE`) + **`--confirm-full-access`** fail-closed, merge không phá hủy `[features]` (bảo toàn cờ người dùng, chỉ khớp stage đang hoạt động, bỏ `js_repl = false`), `web_search`, top-level key & `[section]` của `config.toml`, sinh **4 wrapper** (`codex`, `codex-official`, `codex-t3`, `codex-manage`) với `shell_quote()` (khi bật `--use-git-worktree`, áp dụng **Hard Fail-Closed Worktree Isolation**), và ghi tăng dần (`flush_rollback_manifest`) manifest 5 cột SHA-256 + `original_mode` (`# status=in-progress` $\rightarrow$ `# status=complete`) tại `~/.codex-official/.rollback/latest.tsv`.
* `doctor.sh`: Chạy chỉ-đọc (`set -euo pipefail`, `umask 077`), kiểm tra 6 symlink không gãy/lệch đích, báo cáo **chế độ quyền Sandbox 2 CLI (`Ask` / `Config` `[PASS]`, `danger-full-access` `[WARN]`)**, kiểm tra `[sandbox_workspace_write] network_access = false`, cảnh báo nếu phát hiện plaintext `api_key =` (không in giá trị), chạy **5 live probe `codex execpolicy check`** (`php`, `mshta`, `vssadmin`, `Start-Process`, `iex`), kiểm tra quyền POSIX `0600` (zero-pad octal), kiểm tra chỉ-đọc **Rollback Journal** (`# status=in-progress` hoặc symlink `.rollback`), và chỉ in `auth_mode` đã lọc theo allowlist.
* `restore-original.sh`: Chạy preflight xác thực manifest `.rollback/latest.tsv` (kể cả manifest bán phần `# status=in-progress` sau cài đặt bị ngắt, hoặc `--snapshot PATH`, hỗ trợ cả 4 cột cũ và 5 cột `original_mode` mới, từ chối mode đặc biệt như SUID/SGID/sticky) trước khi đụng đĩa, chặn symlink/path traversal 5 lớp (`assert_safe_contained_path`), kiểm chứng SHA-256 (`sha256sum`/`shasum -a 256`/`openssl dgst -sha256`) và khôi phục **đúng chế độ quyền POSIX ban đầu** (vd `0755` cho launcher cũ, `0644`/`0600` cho config), dùng guard `is_dual_lane_wrapper()` để không xóa launcher cũ chưa chạm tới, hỗ trợ chạy lại nhiều lần (idempotent), tháo sạch symlink trước và kiểm chứng `find -type l` rỗng trước khi `--remove-lane2-home`.

---

## 4. Bảng tham số dòng lệnh đầy đủ

### 4.1. `scripts/setup-dual-lane.ps1` (Windows)

| Tham số | Kiểu | Mặc định | Ý nghĩa |
| :--- | :--- | :--- | :--- |
| `-RepoPath` *(alias: `-ProjectRoot`)* | `string` | Thư mục hiện tại | Đường dẫn dự án muốn đánh dấu `trusted` và (tùy chọn) gắn cầu nối/đồng bộ `Pinned` (hỗ trợ cả đường dẫn tương đối như `-RepoPath .` hoặc `.\sub`) |
| `-CodexPath` | `string` | *(tự dò)* | Đường dẫn thủ công tới `codex.exe` / `codex.cmd` nếu cài ở vị trí đặc biệt |
| `-Lane1Home` | `string` | `%USERPROFILE%\.codex` | Thư mục `CODEX_HOME` của Luồng 1 |
| `-Lane2Home` | `string` | `%USERPROFILE%\.codex-official` | Thư mục `CODEX_HOME` của Luồng 2 |
| `-LocalBin` | `string` | `%USERPROFILE%\.local\bin` | Thư mục lưu 4 launcher `.cmd` (`codex.cmd`, `codex-official.cmd`, `codex-t3.cmd`, `codex-manage.cmd`) cùng 4 POSIX shim không đuôi (`codex`, `codex-official`, `codex-t3`, `codex-manage`) cho Git Bash / MSYS2 |
| `-CargoTargetDir` | `string` | `%TEMP%\codex-lane2-target` | Thư mục build Cargo riêng cho Luồng 2 (đổi sang ổ khác nếu ổ `C:` ít dung lượng) |
| `-OfficialModel` | `string` | *(để trống)* | Đặt model mặc định cố định cho Luồng 2 (vd `<model-slug>` được tài khoản hỗ trợ) |
| `-OfficialReasoning` | `string` | *(để trống)* | Đặt mức suy luận (`low`, `medium`, `high`, `ultra`) nếu muốn cố định |
| `-OfficialServiceTier` | `string` | *(để trống)* | Đặt `service_tier` nếu tài khoản của bạn hỗ trợ |
| `-ApprovalPolicy` | `on-request` \| `never` | `on-request` | Mặc định an toàn (`on-request`); chỉ truyền `never` khi chạy tự động đã cô lập *(lưu ý trên `codex-cli 0.171.0-alpha.13`, giá trị `"untrusted"` đã bị loại bỏ; `config.toml` hỗ trợ `"on-request"`, `"never"`, `"on-failure"` và bảng `granular`)* |
| `-CliMode` | `Ask` \| `Config` \| `FullAccess` | `Ask` | Chọn 3 chế độ quyền cho Luồng 2 (`~/.codex-official/config.toml`): `Ask` (`Xin yêu cầu`: `on-request` + `workspace-write`), `Config` (`Thuộc cấu hình config.toml`: giữ nguyên `approval_policy` & `sandbox_mode` hiện có), hoặc `FullAccess` (`Toàn quyền`: `never` + `danger-full-access`, bắt buộc cảnh báo nguy hiểm & xác nhận tường minh) |
| `-ConfirmFullAccess` | `switch` | `false` | Cờ xác nhận tường minh bắt buộc khi dùng `-CliMode FullAccess` ở chế độ không tương tác (nếu thiếu cờ này và không gõ đúng `TOAN QUYEN`/`I UNDERSTAND`, script **từ chối fail-closed `exit 1`** với `0` thay đổi) |
| `-AllowSandboxNetwork` | `switch` | `false` | Mặc định ngắt mạng trong shell sandbox (`network_access = false`); bật cờ này nếu cần lệnh shell truy cập Internet |
| `-UseGitWorktree` | `switch` | `false` | Tự động tạo Git worktree riêng (`<RepoPath>-lane2`) cho Luồng 2 để cưỡng chế phân quyền ghi ở cấp OS Sandbox |
| `-Lane2WorktreePath` | `string` | `<RepoPath>-lane2` | Đường dẫn tùy chỉnh cho Git worktree của Luồng 2 khi bật `-UseGitWorktree` |
| `-Lane2Branch` | `string` | `dual-lane-2` | Tên nhánh Git dùng cho worktree của Luồng 2 khi bật `-UseGitWorktree` |
| `-ConfigureCliGateway` | `switch` | `false` | Cờ 1 chạm cấu hình API Key / Gateway (`env_key`) tự động nhắm vào **Luồng 2 (`Lane2` — Codex CLI)**, giữ **Luồng 1 (`~/.codex` — Codex Desktop)** nguyên vẹn 100% |
| `-ConfigureGateway` | `switch` | `false` | Bật cấu hình API Key / cổng API tương thích OpenAI (sử dụng `env_key`, không lưu plaintext key trong `config.toml`) |
| `-GatewayTargetLane` | `Lane1` \| `Lane2` \| `Both` | `Lane1` *(hoặc `Lane2` khi dùng `-ConfigureCliGateway`)* | Chọn luồng áp dụng cấu hình API Key / Gateway: `Lane2` (gắn cho Codex CLI `~/.codex-official`, giữ Desktop `~/.codex` ở tài khoản chính `acc chính`), `Lane1` (mặc định tương thích ngược), hoặc `Both` (cả hai luồng) |
| `-GatewayProviderName` | `string` | `OpenAI` | Tên mục `[model_providers.<Name>]` cho luồng đích đã chọn |
| `-GatewayBaseUrl` | `string` | *(trống)* | Base URL của cổng API / endpoint (bắt buộc khi truyền `-ConfigureCliGateway` / `-ConfigureGateway`) |
| `-GatewayModel` | `string` | *(trống)* | Model mặc định cho luồng đích khi dùng `-ConfigureCliGateway` / `-ConfigureGateway` |
| `-GatewayApiKeyEnv` *(alias: `-CliApiKeyEnv`)* | `string` | `CODEX_GATEWAY_API_KEY` | Tên biến môi trường lưu API key cho thuộc tính `env_key` của Codex |
| `-PromptGatewayApiKey` | `switch` | `false` | Nhập ẩn API key lúc chạy qua `Read-Host -AsSecureString` rồi lưu vào biến môi trường User `-GatewayApiKeyEnv` |
| `-GatewayApiKey` | `string` | *(trống)* | *(Tương thích ngược — hạn chế dùng để tránh lưu trong lịch sử PowerShell)* Lưu key vào biến môi trường User `-GatewayApiKeyEnv`, không ghi vào `config.toml` |
| `-ShareAuthToLane2` *(alias: `-ShareOfficialAuth`)* | `switch` | `false` | **Tùy chọn opt-in (tắt mặc định):** Sao chép nguyên tử `~/.codex/auth.json` (nếu có) sang `~/.codex-official/auth.json` kèm sao lưu rollback, khóa ACL 2 bước và cảnh báo `[WARN]` (giữ `~/.codex/auth.json` nguyên vẹn 100%). **Cảnh báo:** Tạo bản sao thứ 2 của `auth.json` trong Luồng 2 — **nên tránh hoặc thận trọng khi Luồng 2 cấu hình cổng API bên thứ 3**. |
| `-TrustRepoPath` | `switch` | `false` | **Tùy chọn opt-in (tắt mặc định — v1.4):** Chỉ ghi `trust_level = "trusted"` cho `-RepoPath` (và worktree Luồng 2 nếu có) khi người dùng chủ động xác nhận bằng cờ này; mặc định không tự nâng mức tin cậy (giữ nguyên `trusted`/`untrusted`/chưa đặt để Codex tự hỏi xác nhận khi mở lần đầu). |
| `-SyncSessions` | `switch` | `false` | Gọi `sync-sessions.py` để đồng bộ UPSERT `session_index.jsonl`, `Pinned` và `Goals` |
| `-PinnedOnlySync` | `switch` | `false` | Khi dùng cùng `-SyncSessions`, chỉ đồng bộ các phiên đã ghim (`Pinned`) |
| `-InstallBridgeTemplate` | `switch` | `false` | Tạo tệp mẫu `artifacts/dual-lane/DUAL_LANE_BRIDGE.md` trong `-RepoPath` |
| `-ReapplyAclOnly` | `switch` | `false` | Chế độ bảo trì nhanh (<1 giây): chỉ chạy lại `Protect-SensitiveFileAcl` fail-closed lên các tệp nhạy cảm hiện có ở cả 2 luồng sau khi Codex sửa `config.toml`/`auth.json` |
| `-SkipPathUpdate` | `switch` | `false` | Bỏ qua bước tự sửa biến môi trường User `PATH` |
| `-DryRun` *(hoặc `-WhatIf`)* | `switch` | `false` | Chạy kiểm tra thực tế và in kế hoạch mà **không sửa bất kỳ tệp hay biến môi trường nào** |

### 4.2. `scripts/restore-original.ps1` (Windows)

| Tham số | Kiểu | Mặc định | Ý nghĩa |
| :--- | :--- | :--- | :--- |
| `-Lane1Home` | `string` | `%USERPROFILE%\.codex` | Thư mục Luồng 1 được caller ủy quyền *(manifest không được phép mở rộng phạm vi ra ngoài)* |
| `-Lane2Home` | `string` | `%USERPROFILE%\.codex-official` | Thư mục Luồng 2 được caller ủy quyền |
| `-LocalBin` | `string` | `%USERPROFILE%\.local\bin` | Thư mục chứa 4 wrapper `.cmd` + 4 POSIX shim (`codex`, `codex-official`, `codex-t3`, `codex-manage`) cần gỡ |
| `-SnapshotPath` | `string` | `<Lane2Home>\.rollback\latest.json` | Đường dẫn tùy chỉnh tới tệp manifest snapshot cụ thể |
| `-RemoveLane2Home` | `switch` | `false` | Xóa thư mục `-Lane2Home` **chỉ sau khi** hoàn tất không lỗi, không thuộc thư mục hệ thống/profile và xác minh 0 NTFS Junction/ReparsePoint còn tồn tại ở mọi độ sâu |
| `-SkipPathUpdate` | `switch` | `false` | Không gỡ `-LocalBin` khỏi biến môi trường User `PATH` |
| `-DryRun` *(hoặc `-WhatIf`)* | `switch` | `false` | Chạy preflight kiểm tra phạm vi đường dẫn, SHA-256 và xem trước toàn bộ thao tác mà không sửa đĩa hay `PATH` |

### 4.3. `scripts/doctor.ps1` (Windows)

| Tham số | Kiểu | Mặc định | Ý nghĩa |
| :--- | :--- | :--- | :--- |
| `-Lane1Home` | `string` | `%USERPROFILE%\.codex` | Thư mục Luồng 1 cần kiểm tra |
| `-Lane2Home` | `string` | `%USERPROFILE%\.codex-official` | Thư mục Luồng 2 cần kiểm tra |
| `-LocalBin` | `string` | `%USERPROFILE%\.local\bin` | Thư mục launcher CLI cần kiểm tra |
| `-CodexPath` | `string` | *(tự dò)* | Đường dẫn tường minh tới `codex.exe` / `codex.cmd` phục vụ 7 probe thực thi `execpolicy check` |

### 4.4. `scripts/setup-dual-lane.sh` (macOS / Linux / WSL)

| Tham số / Biến môi trường | Mặc định | Ý nghĩa |
| :--- | :--- | :--- |
| `--repo PATH` *(hoặc `--repo-path PATH` / đối số vị trí `REPO_PATH`)* | Thư mục hiện tại | Đường dẫn dự án muốn đánh dấu `trusted` (hỗ trợ cả đường dẫn tương đối như `.` hoặc `./sub`) |
| `--approval-policy MODE` *(hoặc `CODEX_APPROVAL_POLICY`)* | `on-request` | `on-request` (mặc định an toàn) hoặc `never` *(lưu ý `"untrusted"` không còn được hỗ trợ trên `codex-cli 0.171.0-alpha.13`)* |
| `--cli-mode MODE` *(hoặc `CODEX_CLI_MODE`)* | `ask` | Chọn 3 chế độ quyền cho Luồng 2 (`~/.codex-official/config.toml`): `ask` (`Xin yêu cầu`: `on-request` + `workspace-write`), `config` (`Thuộc cấu hình config.toml`: giữ nguyên `approval_policy` & `sandbox_mode` hiện có), hoặc `full-access` (`Toàn quyền`: `never` + `danger-full-access`, bắt buộc cảnh báo nguy hiểm & xác nhận tường minh) |
| `--confirm-full-access` | tắt | Xác nhận tường minh bắt buộc khi dùng `--cli-mode full-access` ở chế độ không tương tác (thiếu cờ này và không gõ đúng `TOAN QUYEN`/`I UNDERSTAND` sẽ **từ chối fail-closed `exit 1`** với `0` thay đổi) |
| `--allow-sandbox-network` *(hoặc `CODEX_SANDBOX_NETWORK=true`)* | `false` | Bật `network_access = true` trong `[sandbox_workspace_write]` |
| `--use-git-worktree` | tắt | Tạo Git worktree riêng (`<repo>-lane2`) cho Luồng 2 |
| `--worktree-path PATH` | `<repo>-lane2` | Đường dẫn tùy chỉnh cho worktree Luồng 2 |
| `--configure-cli-gateway` | tắt | Cờ 1 chạm bật cấu hình API Key / Gateway (`env_key`) tự động nhắm vào **Luồng 2 (`lane2` — Codex CLI)**, giữ **Luồng 1 (`~/.codex` — Codex Desktop)** nguyên vẹn 100% |
| `--configure-gateway` | tắt | Bật cấu hình API Key / cổng Gateway qua `env_key` (không lưu plaintext key trong `config.toml`) |
| `--gateway-target-lane LANE` | `lane1` *(hoặc `lane2` khi dùng `--configure-cli-gateway`)* | Chọn luồng áp dụng API Key / Gateway: `lane2` (Codex CLI `~/.codex-official`), `lane1` (Desktop `~/.codex`, mặc định tương thích ngược), hoặc `both` |
| `--gateway-provider NAME` | `OpenAI` | Tên mục `[model_providers."<NAME>"]` khi bật `--configure-cli-gateway` / `--configure-gateway` |
| `--gateway-base-url URL` | *(trống)* | Base URL `http(s)://...` của endpoint API (bắt buộc khi bật `--configure-cli-gateway` / `--configure-gateway`) |
| `--gateway-model SLUG` | *(trống)* | Model mặc định cho luồng đích khi bật `--configure-cli-gateway` / `--configure-gateway` |
| `--gateway-api-key-env VAR` *(alias: `--cli-api-key-env VAR`)* | `CODEX_GATEWAY_API_KEY` | Tên biến môi trường chứa API key được tham chiếu qua `env_key` |
| `--share-auth-to-lane2` *(alias: `--share-official-auth`)* | tắt | **Tùy chọn opt-in (tắt mặc định):** Sao chép nguyên tử `~/.codex/auth.json` (nếu có) sang `~/.codex-official/auth.json` với `chmod 600`, theo dõi rollback và cảnh báo `[WARN]` (giữ `~/.codex/auth.json` nguyên vẹn 100%). **Cảnh báo:** Tạo bản sao thứ 2 của `auth.json` trong Luồng 2 — **nên tránh hoặc thận trọng khi Luồng 2 cấu hình cổng API bên thứ 3**. |
| `--trust-repo-path` | tắt | **Tùy chọn opt-in (tắt mặc định — v1.4):** Chỉ ghi `trust_level = "trusted"` cho `--repo-path` (và worktree Luồng 2 nếu có) khi người dùng chủ động xác nhận bằng cờ này; mặc định không tự nâng mức tin cậy. |
| `--install-bridge` | tắt | Chép `templates/DUAL_LANE_BRIDGE.md` vào `<repo>/artifacts/dual-lane/` |
| `--sync-sessions` | tắt | Chạy `scripts/sync-sessions.py` sau khi cài |
| `--pinned-only` | tắt | Đi cùng `--sync-sessions`, chỉ đồng bộ các phiên đã ghim |
| `--dry-run` | tắt | Xem trước mọi bước mà không ghi tệp nào lên đĩa |
| `CODEX_LANE1_HOME`, `CODEX_LANE2_HOME`, `CODEX_LOCAL_BIN`, `CODEX_CARGO_TARGET_DIR`, `CODEX_LANE2_BRANCH` | `~/.codex`, `~/.codex-official`, `~/.local/bin`, `${TMPDIR:-/tmp}/codex-lane2-target`, `dual-lane-2` | Biến môi trường ghi đè đường dẫn mặc định và tên nhánh worktree trên Unix |
| `CODEX_NO_AUTO_WORKTREE_CD` | *(trống)* | Đặt `=1` để tắt tự động đổi `cwd` vào worktree của wrapper Luồng 2 (cơ chế quét & chặn cờ `-C`/`--cd`/`--add-dir` bảo vệ repo chính vẫn luôn hoạt động fail-closed) |

### 4.5. `scripts/restore-original.sh` & `scripts/doctor.sh` (macOS / Linux / WSL)

* **`scripts/restore-original.sh`:**
  * `--snapshot PATH`: Đường dẫn tùy chỉnh tới manifest SHA-256 TSV (mặc định `<LANE2_HOME>/.rollback/latest.tsv`, tương đương `-SnapshotPath` trên Windows).
  * `--remove-lane2-home`: Xóa `<LANE2_HOME>` chỉ sau khi kiểm chứng không còn bất kỳ symlink nào trong cây thư mục (`find -type l`).
  * `--dry-run`: Chạy preflight xác thực manifest, kiểm chứng SHA-256 và xem trước toàn bộ thao tác mà không sửa đĩa.
  * `-h`, `--help`: Hiển thị hướng dẫn sử dụng.
  * Tôn trọng biến môi trường `CODEX_LANE1_HOME`, `CODEX_LANE2_HOME`, `CODEX_LOCAL_BIN`.
* **`scripts/doctor.sh` (Chỉ đọc — Read-Only):**
  * `--lane1 PATH`, `--lane2 PATH`, `--local-bin PATH`: Chỉ định tường minh thư mục cần chẩn đoán (cũng tôn trọng `CODEX_LANE1_HOME`, `CODEX_LANE2_HOME`, `CODEX_LOCAL_BIN`).
  * `-h`, `--help`: Hiển thị hướng dẫn sử dụng.

### 4.6. `scripts/sync-sessions.py` (Đa nền tảng — v1.4.0)

| Tham số | Mặc định | Ý nghĩa |
| :--- | :--- | :--- |
| `--source` *(alias: `--lane1`)* | `~/.codex` | Thư mục `CODEX_HOME` nguồn (mở SQLite ở chế độ `?mode=ro` khi đọc) |
| `--target` *(alias: `--lane2`)* | `~/.codex-official` | Thư mục `CODEX_HOME` đích |
| `--bidirectional` | `false` | Đồng bộ an toàn **2 chiều** (`source -> target` và `target -> source`) để GPT 1 và Sandbox 2 hội tụ đủ 100% phiên chat, `Pinned` & `Goals` mà vẫn bảo toàn `is_pinned = 1` và không bao giờ ghi đè metadata `updated_at` mới hơn của GPT 1 |
| `--backup-target` | `false` | Tạo bản sao lưu SQLite an toàn (`<db>.sync-backup-<timestamp>` qua SQLite online `.backup()`) trước khi ghi xuống DB đích (bỏ qua khi `--dry-run`) |
| `--rescue-shared-files` | `false` | Kiểm tra 4 thư mục dùng chung (`sessions`, `archived_sessions`, `memories`, `memories_v2`) trong `--source`: nếu đã là Junction/symlink thì bỏ qua sạch; nếu là thư mục cục bộ thật thì sao chép **không ghi đè** các tệp thường còn thiếu sang `--target` (từ chối symlink fail-closed) |
| `--repo` | *(tùy chọn)* | Gán `cwd` cho các phiên `is_pinned = 1` để `codex resume` trong dự án hiện ngay |
| `--approval-mode` | *(giữ nguyên)* | Gán `never` hoặc `on-request` cho các phiên đồng bộ |
| `--pinned-only` | `false` | Chỉ đồng bộ các phiên đã ghim (`is_pinned = 1` hoặc thuộc section), không kéo phiên chưa ghim |
| `--dry-run` | `false` | Chỉ kiểm tra schema, đếm bản ghi và mô phỏng cứu hộ tệp, tuyệt đối không ghi xuống SQLite/JSONL/đĩa |

### 4.7. `scripts/codex-manager.ps1` (Windows) & `scripts/codex-manager.sh` (macOS / Linux / WSL) — Trung tâm Điều khiển Sandbox 2 (`codex-manage`)

| Windows (`codex-manager.ps1`) | Unix (`codex-manager.sh`) | Mặc định | Ý nghĩa |
| :--- | :--- | :--- | :--- |
| `-Action` | `--action` | `Menu` / `menu` | Chọn tác vụ: `Menu`/`menu`, `ApiGpt`/`api-gpt`, `ApiOther`/`api-other`, `Login`/`login`, `CheckApiKey`/`check-api-key`, `CheckAccounts`/`check-accounts`, `SyncHistory`/`sync-history`, `RemoveSandbox2`/`remove-sandbox2`, `SetCliMode`/`set-cli-mode` |
| `-CliMode` | `--cli-mode` | *(hỏi chọn trong menu `[7]`)* | Dùng cùng `SetCliMode`/`set-cli-mode`: chọn `Ask`/`ask` (`Xin yêu cầu`: `on-request` + `workspace-write`), `Config`/`config` (`Thuộc cấu hình config.toml`: giữ nguyên `approval_policy` & `sandbox_mode`), hoặc `FullAccess`/`full-access` (`Toàn quyền`: `never` + `danger-full-access`, bắt buộc cảnh báo nguy hiểm & xác nhận fail-closed) |
| `-ConfirmFullAccess` | `--confirm-full-access` | `false` | Xác nhận tường minh bắt buộc khi chạy `SetCliMode`/`set-cli-mode` với `FullAccess`/`full-access` ở chế độ không tương tác (thiếu xác nhận này hoặc không gõ `TOAN QUYEN`/`I UNDERSTAND` $\rightarrow$ **từ chối fail-closed `exit 1`**, `0` thay đổi `config.toml`; `-Force`/`--force` một mình **không bao giờ** vượt qua cổng này) |
| `-Lane1Home` | `--lane1-home` | `~/.codex` | Thư mục `CODEX_HOME` của **GPT 1** (Codex Desktop) |
| `-Lane2Home` | `--lane2-home` | `~/.codex-official` | Thư mục `CODEX_HOME` của **Sandbox 2** (Codex CLI) |
| `-LocalBin` | `--local-bin` | `~/.local/bin` | Thư mục chứa 4 launcher CLI (`codex`, `codex-official`, `codex-t3`, `codex-manage`) |
| `-CodexPath` | `--codex-path` | *(tự dò)* | Đường dẫn tường minh tới tệp thực thi `codex` |
| `-OnlineCheck` | `--online-check` | `false` | Dùng cùng `CheckApiKey`/`check-api-key`: gửi probe `GET <base_url>/models` an toàn qua bộ nhớ tiến trình **chỉ qua HTTPS** (loopback `http://127.0.0.1`/`localhost`/`::1` chỉ dành cho test cục bộ) với **tắt tự động redirect** để kiểm tra `200 OK` / `401` / `429` / `REFUSED` / `REDIRECT_BLOCKED` / `NETWORK_ERROR` (0 rò rỉ key) |
| `-DeviceAuth` | `--device-auth` | `false` | Dùng cùng `Login`/`login`: chạy `codex login --device-auth` cho môi trường terminal/SSH không mở trình duyệt |
| `-Editor` | `--editor` | `$env:EDITOR` / `notepad.exe` *(Unix: `${VISUAL:-${EDITOR:-vi}}`)* | Trình soạn thảo mở trực tiếp `~/.codex-official/config.toml` khi chạy `ApiOther`/`api-other` |
| `-ApiKeySecure` | *(chỉ Windows)* | *(trống)* | Truyền `[SecureString]` trong kịch bản PowerShell tự động cho `ApiGpt` (tuyệt đối không chấp nhận chuỗi plaintext trên CLI argv) |
| `-ApiKeyFromStdin` | `--api-key-from-stdin` | `false` | Đọc API key từ `stdin` cho `ApiGpt`/`api-gpt` trong kịch bản tự động (không để lại key trong lịch sử lệnh hay `ps`) |
| `-NonInteractive` | `--non-interactive` | `false` | Chạy không dừng hỏi tương tác (dùng cho tự động hóa & CI) |
| `-Force` | `--force` | `false` | Bỏ qua bước hỏi xác nhận khi dọn `model_provider` (`Login`) hoặc xóa Sandbox 2 (`RemoveSandbox2`/`remove-sandbox2`) — **vẫn luôn bắt buộc chạy bước cứu hộ lịch sử chat fail-closed trước khi xóa và KHÔNG BAO GIỜ vượt qua cổng xác nhận `FullAccess`!** |
| `-DryRun` | `--dry-run` | `false` | Chạy mô phỏng toàn bộ quy trình (kể cả `SyncHistory` và `RemoveSandbox2`/`remove-sandbox2`) mà không ghi hay xóa 1 byte nào trên đĩa |

---

## 5. Xóa Sandbox 2 Không Mất Lịch Sử Chat (v1.4.0) & Cơ chế Khôi phục Chính xác 1 Chạm (Deterministic SHA-256 Rollback)

### 5.1. Xóa Sandbox 2 (`~/.codex-official` — Codex CLI) mà Giữ Nguyên 100% Lịch Sử Chat về GPT 1 (`~/.codex`)

Khi bạn không muốn dùng Sandbox 2 (Codex CLI) nữa nhưng muốn chắc chắn **mọi cuộc trò chuyện, phiên `Pinned`, `Goals` và tệp rollout/memory tạo ra ở Sandbox 2 đều được bảo toàn 100% trong GPT 1 (Codex Desktop)**, hãy dùng **`codex-manage`** (mục `[6]`) hoặc chạy trực tiếp:

```powershell
# Windows (PowerShell):
.\scripts\codex-manager.ps1 -Action RemoveSandbox2 -DryRun
.\scripts\codex-manager.ps1 -Action RemoveSandbox2
```
```bash
# macOS / Linux / WSL:
./scripts/codex-manager.sh --action remove-sandbox2 --dry-run
./scripts/codex-manager.sh --action remove-sandbox2
```

Quy trình **3 bước fail-closed** đảm bảo 0 mất mát dữ liệu:
1. **Bước 1 (Bắt buộc — Cứu hộ ngược về GPT 1 trước khi xóa):** Chạy `scripts/sync-sessions.py --source <Lane2Home> --target <Lane1Home> --rescue-shared-files --backup-target` (tạo bản sao lưu `.sync-backup-*` cho SQLite GPT 1 trước khi ghi, hợp nhất đầy đủ `session_index.jsonl`, `state_*.sqlite`, `goals_*.sqlite`, bảo toàn `is_pinned = 1` và không bao giờ ghi đè metadata `updated_at` mới hơn của GPT 1, đồng thời sao chép không ghi đè mọi tệp rollout/memory cục bộ nếu thư mục không phải Junction/symlink). **Nếu bước này lỗi, script dừng ngay (fail-closed) và KHÔNG xóa Sandbox 2.**
2. **Bước 2 (Tháo liên kết trước — Xóa Sandbox 2 sau):** Gọi `scripts/restore-original.ps1 -RemoveLane2Home` (Windows) hoặc `scripts/restore-original.sh --remove-lane2-home` (Unix) để tháo sạch toàn bộ NTFS Junction/symlink trước, xác minh `0` reparse point / `find -type l` rỗng ở mọi độ sâu, hoàn nguyên cấu hình theo SHA-256, rồi mới xóa `~/.codex-official` và 4 wrapper CLI.
3. **Bước 3 (Hậu kiểm GPT 1):** Xác minh các thư mục lịch sử chat của GPT 1 (`~/.codex/sessions`, `memories`, `state_*.sqlite`) còn nguyên vẹn 100%.

### 5.2. Khôi phục Thuần theo Snapshot SHA-256 (`restore-original.*`)

Mỗi khi chạy `setup-dual-lane.ps1` (Windows) hoặc `setup-dual-lane.sh` (macOS / Linux / WSL), bộ cài khởi tạo **nhật ký rollback tăng dần chống crash (Crash-Safe Incremental Rollback Journal)** tại `~/.codex-official/.rollback/latest.json` (Windows, `Completed: false -> true`) hoặc `~/.codex-official/.rollback/latest.tsv` (Unix, `# status=in-progress -> complete`), kèm bản lịch sử `snapshot-yyyyMMdd-HHmmss[-N].*`, và cập nhật nguyên tử **ngay sau từng thao tác** (tạo Junction/symlink, tính SHA-256 & sao lưu tệp cấu hình gốc, cài từng launcher kể cả `codex-manage`).

Từ **v1.3.1 (Manifest Schema Version 2)**, cơ chế rollback được nâng cấp toàn diện:
1. **Xác định chính xác quyền sở hữu liên kết (`SharedLinkRecords` / dòng `L`):** Ghi nhận trạng thái ban đầu (`absent`, `preexisting_link`, `preexisting_dir`) và cờ `CreatedByKit`. Nếu thư mục đích đã là Junction hoặc symlink từ trước khi cài kit, rollback sẽ **bảo toàn nguyên vẹn liên kết đó** và chỉ gỡ các liên kết do kit thực sự tạo ra.
2. **Khôi phục thư mục theo đường dẫn chính xác:** Khi chuyển thư mục thật có từ trước thành bản sao lưu, đường dẫn sao lưu chính xác (`BackupDirPath` / `dir_bkp`) được lưu trong manifest. Rollback khôi phục đúng từ thư mục đó thay vì tìm kiếm sắp xếp tên wildcard `.backup-*` (loại bỏ hoàn toàn rủi ro khôi phục nhầm bản backup cũ hoặc decoy).
3. **Kiểm tra tiền trạm (Preflight) nghiêm ngặt Fail-Closed:** Trước khi thực hiện Bước 1 (tháo liên kết hay thay đổi bất kỳ tệp nào), script kiểm tra toàn bộ bản sao lưu tệp và thư mục. Nếu phát hiện thiếu bất kỳ bản sao lưu bắt buộc nào và đích chưa ở trạng thái gốc, script lập tức **báo lỗi và dừng với mã thoát `1`**, không làm thay đổi bất kỳ trạng thái nào trên đĩa.

Nhờ vậy ngay cả khi quá trình cài bị ngắt giữa chừng (`Ctrl+C`/lỗi) hoặc môi trường có sẵn cấu hình liên kết phức tạp, bạn vẫn có thể chạy `restore-original.*` để hoàn nguyên sạch toàn bộ thay đổi bán phần mà không mất dữ liệu Luồng 1 hay xóa nhầm launcher/link cũ chưa chạm tới.

Khi muốn quay về **chính xác 100% trạng thái ban đầu đến từng byte**, hãy chạy `scripts/restore-original.ps1` (hoặc `scripts/restore-original.sh` trên Unix):

```powershell
# Bước 1 (Khuyên dùng): Xem trước kế hoạch khôi phục & kiểm chứng khớp SHA-256 mà không sửa đĩa
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1 -DryRun

# Bước 2: Thực thi khôi phục chính xác về trạng thái trước khi cài (giữ lại thư mục ~/.codex-official)
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1

# Hoặc: Khôi phục chính xác VÀ dọn sạch hoàn toàn ~/.codex-official (sau khi đã xác minh tháo sạch 6 NTFS Junction)
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1 -RemoveLane2Home
```

*(Trên macOS / Linux / WSL: chạy `./scripts/restore-original.sh --dry-run` rồi `./scripts/restore-original.sh --remove-lane2-home`).*

### Quy trình gỡ thủ công (nếu bạn không còn giữ thư mục bộ kit)

> [!CAUTION]
> **Rất quan trọng khi gỡ trên Windows:** Các thư mục `memories`, `memories_v2`, `sessions`, `archived_sessions`, `skills`, `plugins` bên trong `~/.codex-official` là **NTFS Directory Junction** trỏ tới dữ liệu thật trong `~/.codex`.
> Hãy **gỡ từng Junction bằng `cmd /c rmdir` trước** khi xóa thư mục `~/.codex-official` để tuyệt đối không làm mất dữ liệu lịch sử gốc trong `~/.codex`!

```powershell
# 1. Gỡ an toàn 6 NTFS Junction (chỉ gỡ liên kết, giữ nguyên 100% dữ liệu gốc trong ~/.codex):
foreach ($d in @('memories','memories_v2','sessions','archived_sessions','skills','plugins')) {
    $p = Join-Path "$env:USERPROFILE\.codex-official" $d
    if (Test-Path -LiteralPath $p) { cmd /c rmdir "$p" }
}

# 2. Xóa phần còn lại của ~/.codex-official và 4 launcher CLI (.cmd + POSIX shim):
Remove-Item "$env:USERPROFILE\.codex-official" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\.local\bin\codex.cmd", `
            "$env:USERPROFILE\.local\bin\codex-official.cmd", `
            "$env:USERPROFILE\.local\bin\codex-t3.cmd", `
            "$env:USERPROFILE\.local\bin\codex-manage.cmd", `
            "$env:USERPROFILE\.local\bin\codex", `
            "$env:USERPROFILE\.local\bin\codex-official", `
            "$env:USERPROFILE\.local\bin\codex-t3", `
            "$env:USERPROFILE\.local\bin\codex-manage" -Force -ErrorAction SilentlyContinue

# 3. (Nếu muốn khôi phục ~/.codex/config.toml về bản gốc trước khi chạy -ConfigureGateway):
if (Test-Path "$env:USERPROFILE\.codex\config.backup.toml") {
    Copy-Item "$env:USERPROFILE\.codex\config.backup.toml" "$env:USERPROFILE\.codex\config.toml" -Force
}
```
