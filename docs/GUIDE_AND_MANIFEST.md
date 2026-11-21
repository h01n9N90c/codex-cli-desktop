# Hướng dẫn Chi tiết & Khai báo Mã nguồn / Công cụ (Manifest)

> **Tác giả:** **Lê Hoàng Ngọc Tươi** | **Giấy phép:** Apache License 2.0 ([LICENSE](../LICENSE) · [NOTICE](../NOTICE))  
> Tài liệu này minh bạch hóa **100% từng tệp mã nguồn, từng hàm thực thi, tham số dòng lệnh, đường dẫn đọc/ghi và giới hạn tác động** trong bộ **Codex Dual-Lane & Security Kit**, để bất kỳ lập trình viên hay đội kiểm duyệt an ninh nào cũng có thể kiểm chứng trước khi chạy.

---

## 1. Cam kết minh bạch an ninh (Những gì bộ công cụ TUYỆT ĐỐI KHÔNG làm)

* **Không kết nối Internet / không tải mã từ xa:** Toàn bộ script chạy cục bộ 100% trên máy của bạn; không gọi `Invoke-WebRequest`, `curl`, `wget` hay gửi telemetry ra ngoài.
* **Không đòi quyền Administrator bắt buộc:** Mọi thao tác (`Get-AppxPackage`, tạo NTFS Directory Junction trong `%USERPROFILE%`, sửa `User PATH`, đọc/ghi `~/.codex*`) đều chạy ở quyền người dùng thường.
* **Không chứa API key, token hay mock data:** Mọi thông số máy (phiên bản Windows, ổ đĩa, NTFS, dung lượng trống, đường dẫn `codex.exe`, danh sách feature flags, bảng cột SQLite) đều được đọc trực tiếp từ hệ thống thật tại thời điểm chạy.
* **Không xóa đè cấu hình gốc không sao lưu:** Mọi tệp cấu hình/rule/`AGENTS.md` cũ đều được sao lưu với hậu tố `.backup-yyyyMMdd-HHmmss` trước khi ghi.

---

## 2. Khai báo chi tiết toàn bộ tệp mã nguồn & công cụ

### 2.1. Công cụ thực thi (`scripts/`)

| Tệp | Ngôn ngữ / Runtime | Vai trò chính | Đường dẫn ĐỌC | Đường dẫn GHI |
| :--- | :--- | :--- | :--- | :--- |
| [`scripts/setup-dual-lane.ps1`](../scripts/setup-dual-lane.ps1) | PowerShell 5.1+ / 7+ (Windows) | Bộ cài đặt chính 1 chạm cho Windows (hỗ trợ `-DryRun`) | `Get-AppxPackage OpenAI.Codex`, `PATH`, `Get-Volume`, `codex features list`, `templates/*`, `config.toml` cũ | `~/.codex-official/config.toml`, `~/.codex*/rules/default.rules`, `~/.codex*/AGENTS.md`, 6 NTFS Junctions trong `~/.codex-official/`, 3 wrapper `.cmd` trong `~/.local/bin/`, User `PATH`, tùy chọn `~/.codex/config.toml` & `<repo>/artifacts/dual-lane/DUAL_LANE_BRIDGE.md` |
| [`scripts/setup-dual-lane.sh`](../scripts/setup-dual-lane.sh) | Bash (`set -euo pipefail`, macOS / Linux / WSL) | Bộ cài đặt tương đương cho hệ Unix | `which -a codex`, `templates/*` | `~/.codex-official/config.toml`, 6 symlinks (`ln -s`), `rules/default.rules`, `AGENTS.md`, 3 wrapper shell trong `~/.local/bin/` |
| [`scripts/doctor.ps1`](../scripts/doctor.ps1) | PowerShell 5.1+ / 7+ (Windows) | Kiểm tra sức khỏe, tương thích hệ thống & trạng thái cách ly phân tích tĩnh (**Chỉ đọc — Read-Only**) | `OSVersion`, `Get-Volume`, `Get-Command codex/codex-t3/python`, thuộc tính Junction, `default.rules`/`AGENTS.md`/`config.toml`, `auth.json` *(chỉ đọc trường `auth_mode`, không in giá trị token/key)* | **Không ghi bất kỳ tệp nào** |
| [`scripts/sync-sessions.py`](../scripts/sync-sessions.py) | Python 3.8+ (thư viện chuẩn `sqlite3`, `json`, `glob`, `re`) | Đồng bộ tên phiên, mục đã ghim (`Pinned`) & `Goals` từ Luồng 1 sang Luồng 2 (hỗ trợ `--dry-run`) | `~/.codex/session_index.jsonl`, `~/.codex/state_*.sqlite`, `~/.codex/goals_*.sqlite`, `PRAGMA table_info(...)` | `~/.codex-official/session_index.jsonl`, `~/.codex-official/state_*.sqlite`, `~/.codex-official/goals_*.sqlite` *(kèm `PRAGMA wal_checkpoint(TRUNCATE)`)* |

### 2.2. Tệp mẫu chính sách & phối hợp (`templates/`)

| Tệp | Mục đích & Hành vi thực thi |
| :--- | :--- |
| [`templates/default.rules`](../templates/default.rules) | Bộ luật **Execpolicy (Starlark)** nạp vào tầng Rust của Codex: chặn cứng (`forbidden`) nhóm lệnh phá hệ thống/cài persistence (`vssadmin`, `bcdedit`, `wbadmin`, `diskpart`, `format`, `schtasks`, `sc`, `sc.exe`, `reg add/delete/import`, `git push --force/-f`), chặn trình thông dịch & Windows LOLBins để ép phân tích tĩnh (`php`, `ruby`, `perl`, `cscript`, `wscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `msiexec`, `wmic`, `Start-Process`, `Invoke-Expression`, `iex`), và bắt buộc hỏi xác nhận (`prompt`) với `git push`, `git reset --hard`, `git clean`. |
| [`templates/AGENTS.lane1.md`](../templates/AGENTS.lane1.md) | Chỉ thị toàn cục cài vào `~/.codex/AGENTS.md` cho **Luồng 1**: chống Prompt Injection, **cách ly chỉ phân tích tĩnh (cấm thực thi tệp mẫu/nhị phân)**, cấm đọc/in `config.toml`/`auth.json`/`.env`/`.ssh/`, giữ kỷ luật artifact và tuân thủ phân vùng trong `DUAL_LANE_BRIDGE.md`. |
| [`templates/AGENTS.lane2.md`](../templates/AGENTS.lane2.md) | Chỉ thị toàn cục cài vào `~/.codex-official/AGENTS.md` cho **Luồng 2**: cùng chuẩn bảo vệ & cách ly phân tích tĩnh với Luồng 1, bổ sung luật **Zero-Collision** (không sửa vùng file/catalog của Luồng 1, dùng `CARGO_TARGET_DIR` riêng, đọc chéo handoff của Luồng 1). |
| [`templates/DUAL_LANE_BRIDGE.md`](../templates/DUAL_LANE_BRIDGE.md) | Tệp cầu nối mẫu để chép vào dự án của bạn (`artifacts/dual-lane/DUAL_LANE_BRIDGE.md`), khai báo ranh giới thư mục được phép ghi của Luồng 1 vs Luồng 2, hợp đồng giao tiếp chung và bảng trạng thái đồng bộ. |

### 2.3. Tài liệu & cấu hình repo (`docs/`, gốc repo)

| Tệp | Nội dung |
| :--- | :--- |
| [`README.md`](../README.md) | Trang tổng quan, bảng chọn kịch bản theo nhu cầu, sơ đồ kiến trúc và lệnh cài nhanh 3 bước. |
| [`docs/GUIDE_AND_MANIFEST.md`](./GUIDE_AND_MANIFEST.md) | Chính tài liệu bạn đang đọc — khai báo chi tiết mã nguồn, hàm, tham số và hướng dẫn gỡ bỏ. |
| [`docs/SECURITY_MODEL.md`](./SECURITY_MODEL.md) | Phân tích sâu 4 lớp bảo vệ, cách ly chỉ phân tích tĩnh, nguyên tắc Khiên Git và rủi ro khi dùng cổng API bên thứ 3. |
| [`docs/TROUBLESHOOTING.md`](./TROUBLESHOOTING.md) | Hướng dẫn khắc phục 7 lỗi thực chiến thường gặp (bao gồm cảnh báo nhầm Windows Defender trên file `.jsonl`). |
| [`.gitignore`](../.gitignore) | Chặn tuyệt đối không để lỡ commit `.env`, `config.toml`, `auth.json`, `*.sqlite`, `*.key`, `__pycache__/`. |
| [`LICENSE`](../LICENSE) | Giấy phép mã nguồn mở **Apache License 2.0**. |
| [`NOTICE`](../NOTICE) | Thông báo bản quyền chuẩn Apache-2.0 (`Copyright 2026 Lê Hoàng Ngọc Tươi`). |

---

## 3. Diễn giải chi tiết từng bước thực thi của các script

### 3.1. Luồng chạy 12 bước của `scripts/setup-dual-lane.ps1`

1. **Dò tệp thực thi Codex (`Resolve-CodexExecutable`):**
   * Thứ tự ưu tiên: `-CodexPath` $\rightarrow$ gói `OpenAI.Codex` trong `WindowsApps` $\rightarrow$ lệnh `codex` trong `PATH` *(tự loại trừ thư mục `~/.local/bin` để tránh tự gọi đệ quy chính wrapper)* $\rightarrow$ `%APPDATA%\npm\codex.cmd` và `%LOCALAPPDATA%\Programs\Codex\codex.exe`.
   * Nếu không tìm thấy bản Codex nào, dừng sớm và báo lỗi rõ ràng (fail-closed).
2. **Kiểm tra ổ đĩa & NTFS (`Get-Volume`):**
   * Kiểm tra ổ chứa `-Lane2Home` có dùng hệ thống tệp **NTFS** không (điều kiện bắt buộc của NTFS Directory Junction).
   * Kiểm tra dung lượng trống thực tế của ổ chứa `-CargoTargetDir`; cảnh báo nếu dưới `10 GB`.
3. **Dò thật Feature Flags (`Get-SupportedCodexFeatures`):**
   * Tạo thư mục tạm riêng, gọi `& $CodexExe features list` với `CODEX_HOME` tạm để lấy đúng các flag mà bản Codex trên máy hỗ trợ (ví dụ `daemon_auto_start`, `memories`, `js_repl`, `goals`, `api_key_model_discovery`, `image_generation`).
   * Xóa ngay thư mục tạm trong khối `finally`.
4. **Chuẩn bị thư mục:** Tạo `~/.codex`, `~/.codex/rules`, `~/.codex-official`, `~/.codex-official/rules`, `~/.local/bin` nếu chưa có.
5. **Tạo 6 NTFS Directory Junction:** Nối `memories`, `memories_v2`, `sessions`, `archived_sessions`, `skills`, `plugins` từ `~/.codex-official` trỏ sang `~/.codex`. Nếu đã là Junction thì giữ nguyên, không xóa dữ liệu gốc.
6. **Cài đặt tường lửa lệnh:** Sao lưu file cũ (nếu có) và chép `templates/default.rules` vào cả 2 luồng.
7. **Cài đặt `AGENTS.md` toàn cục:** Sao lưu file cũ (nếu có) và chép `AGENTS.lane1.md` vào `~/.codex/AGENTS.md`, `AGENTS.lane2.md` vào `~/.codex-official/AGENTS.md`.
8. **Tạo `~/.codex-official/config.toml` (Luồng 2 Chính chủ):**
   * Quét giữ lại toàn bộ `[projects.'...']` đã `trusted` từ cả `config.toml` cũ của Luồng 1 & Luồng 2 (`Get-ExistingTrustedProjects`) rồi bổ sung `-RepoPath`.
   * Escape chuẩn ký tự `\` và `"` trong chuỗi TOML (`Escape-TomlBasicString`) để chạy an toàn với đường dẫn có dấu cách, tiếng Việt hoặc `&`.
   * Chỉ ghi `model` / `model_reasoning_effort` / `service_tier` nếu bạn truyền tham số tương ứng (mặc định để trống cho Codex tự chọn theo gói tài khoản thật).
   * Tự đặt `daemon_auto_start = false` (nếu binary hỗ trợ) để khắc phục lỗi `this CLI has no complete local package`.
   * Gán `CODEX_ACTIVE_LANE = "LANE_2"` và `CARGO_TARGET_DIR` trong `[shell_environment_policy.set]`, kèm danh sách lọc `exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]`.
9. ***(Tùy chọn `-ConfigureGateway`)* Cấu hình cổng API bên thứ 3 cho Luồng 1:**
   * Chỉ chạy khi truyền đủ `-ConfigureGateway`, `-GatewayBaseUrl`, `-GatewayApiKey`.
   * Lưu riêng bản sạch gốc `~/.codex/config.backup.toml` (chỉ tạo nếu chưa có) trước khi ghi `~/.codex/config.toml`.
10. **Tạo 3 bộ gọi CLI trong `~/.local/bin/`:**
    * `codex.cmd` và `codex-official.cmd` $\rightarrow$ đặt `CODEX_HOME=~/.codex-official`, `CODEX_ACTIVE_LANE=LANE_2`, `CARGO_TARGET_DIR=<target>`.
    * `codex-t3.cmd` $\rightarrow$ đặt `CODEX_HOME=~/.codex`, `CODEX_ACTIVE_LANE=LANE_1`.
    * Với bản `WindowsApps`, wrapper tự kiểm tra `if not exist "%CODEX_EXE%"` để tự dò lại qua `Get-AppxPackage OpenAI.Codex` khi Microsoft Store cập nhật phiên bản mới.
    * Nếu `~/.local/bin` chưa nằm trong User `PATH`, tự thêm vào User `PATH`.
11. ***(Tùy chọn `-InstallBridgeTemplate`)* Chép mẫu `DUAL_LANE_BRIDGE.md`:** Tạo `<RepoPath>\artifacts\dual-lane\DUAL_LANE_BRIDGE.md` nếu chưa tồn tại (không ghi đè file đã có).
12. ***(Tùy chọn `-SyncSessions`)* Đồng bộ phiên & xác minh:** Gọi `scripts/sync-sessions.py` (nếu máy có Python 3) và chạy kiểm chứng `codex.cmd --version`.

### 3.2. Bản đồ Chi tiết Các Hàm trong từng Tệp Mã nguồn

#### `scripts/setup-dual-lane.ps1` (PowerShell 5.1+ / 7+)
| Tên hàm | Đầu vào | Thực hiện chính xác điều gì |
| :--- | :--- | :--- |
| `Write-Step` | `Message` | In tiêu đề từng bước cài đặt có màu sắc rõ ràng trên Console. |
| `Escape-TomlBasicString` | `Value` | Escape ký tự `\` và `"` thành chuỗi TOML hợp lệ (an toàn với đường dẫn có dấu cách, tiếng Việt, ký tự `&`). |
| `Write-Utf8NoBom` | `FilePath`, `Text` | Ghi tệp `config.toml` và `.cmd` theo chuẩn **UTF-8 không BOM** (tránh lỗi TOML parser trên Windows PowerShell 5.1 và giữ nguyên dấu tiếng Việt/Unicode trên tên người dùng Windows). |
| `Backup-IfExists` | `FilePath` | Kiểm tra file đích; nếu đã tồn tại thì sao lưu sang `<FilePath>.backup-yyyyMMdd-HHmmss` trước khi ghi đè (tôn trọng `-DryRun`). |
| `Resolve-CodexExecutable` | `ExplicitPath`, `ExcludedDir` | Tự dò đường dẫn thật của `codex.exe`/`codex.cmd` theo 4 nguồn: tham số `-CodexPath` $\rightarrow$ `WindowsApps` (`OpenAI.Codex`) $\rightarrow$ `PATH` *(loại trừ `~/.local/bin` tránh vòng lặp đệ quy)* $\rightarrow$ `%APPDATA%\npm` & `%LOCALAPPDATA%\Programs`. |
| `Get-SupportedCodexFeatures` | `ExePath`, `ProbeHome` | Chạy thử `& $ExePath features list` trong một thư mục tạm `CODEX_HOME` riêng để lấy danh sách feature flags thật mà bản Codex trên máy hỗ trợ, rồi dọn sạch thư mục tạm. |
| `Get-ExistingTrustedProjects` | `ConfigPaths[]` | Quét các `config.toml` cũ của cả Luồng 1 & Luồng 2 để giữ nguyên 100% danh sách `[projects.'...']` đã đánh dấu `trusted`. |

#### `scripts/doctor.ps1` (PowerShell 5.1+ / 7+ — Chỉ đọc)
| Thành phần / Mục kiểm tra | Thực hiện chính xác điều gì |
| :--- | :--- |
| `Report` | Định dạng và thống kê 3 trạng thái `[PASS]` / `[WARN]` / `[FAIL]`; thoát mã `1` nếu có lỗi `[FAIL]`. |
| 7 nhóm kiểm tra thật | (1) OS & PowerShell; (2) Toàn bộ ổ đĩa cố định, NTFS & dung lượng trống thật; (3) Đường dẫn + phiên bản `codex` & `codex-t3` trong `PATH`; (4) Tình trạng 6/6 NTFS Directory Junction; (5) Đầy đủ `config.toml` + `default.rules` + `AGENTS.md`, trạng thái cách ly chỉ phân tích tĩnh (`static-only=ON`) & mạng sandbox (`sandbox_net=restricted/enabled`) cho cả 2 luồng; (6) Cách ly `auth.json` *(chỉ đọc `auth_mode`, không bao giờ in token/key)*; (7) Tình trạng Python 3 phục vụ đồng bộ phiên. |

#### `scripts/sync-sessions.py` (Python 3.8+ — Chỉ dùng thư viện chuẩn)
| Tên hàm | Đầu vào | Thực hiện chính xác điều gì |
| :--- | :--- | :--- |
| `find_latest_versioned_db` | `directory`, `prefix` | Tự dò file SQLite phiên bản mới nhất (`state_*.sqlite`, `goals_*.sqlite`) theo số thứ tự lớn nhất. |
| `get_tables` / `get_columns` | `conn`, `table` | Truy vấn `sqlite_master` và `PRAGMA table_info(...)` để tương thích động mọi phiên bản schema Codex. |
| `sync_session_index` | `lane1`, `lane2`, `dry_run` | Hợp nhất không trùng lặp các bản ghi theo `id` giữa 2 tệp `session_index.jsonl`. |
| `copy_shared_table` | `c1`, `c2`, `table`, `dry_run` | Chỉ sao chép phần giao các cột tồn tại ở cả 2 DB (`INSERT OR REPLACE`), tránh lỗi khi lệch phiên bản DB. |
| `sync_state_db` | `lane1`, `lane2`, `repo_path`, `approval_mode`, `dry_run` | Đồng bộ `thread_sections`, `projects`, `project_roots`, `threads` (giữ tên, trạng thái `is_pinned`, chuẩn hóa `model_provider = 'openai'`, tùy chọn gắn `cwd` & `approval_mode`) và ép `PRAGMA wal_checkpoint(TRUNCATE)`. |
| `sync_goals_db` | `lane1`, `lane2`, `dry_run` | Đồng bộ bảng `thread_goals` và `thread_goal_continuation_deferrals`, kèm `PRAGMA wal_checkpoint(TRUNCATE)`. |
| `main` | Tham số CLI (`argparse`) | Điều phối 3 bước đồng bộ trên và in báo cáo tổng hợp (`[OK]` hoặc `[DRY-RUN]`). |

#### `scripts/setup-dual-lane.sh` (Bash — macOS / Linux / WSL)
* Chạy với `set -euo pipefail`, tự tìm binary `codex` ngoài `~/.local/bin`, tạo 6 symbolic links (`ln -s`) chia sẻ bộ nhớ/phiên/kỹ năng/plugin, sao lưu có dấu thời gian rồi cài `default.rules`, `AGENTS.lane1.md`, `AGENTS.lane2.md`, `config.toml` (mặc định `network_access = false`, đổi được qua biến `CODEX_SANDBOX_NETWORK=true`), và sinh 3 wrapper chạy lệnh (`codex`, `codex-official`, `codex-t3`).

---

## 4. Bảng tham số dòng lệnh đầy đủ

### 4.1. `scripts/setup-dual-lane.ps1`

| Tham số | Kiểu | Mặc định | Ý nghĩa |
| :--- | :--- | :--- | :--- |
| `-RepoPath` | `string` | Thư mục hiện tại | Đường dẫn dự án muốn đánh dấu `trusted` và (tùy chọn) gắn cầu nối/đồng bộ `Pinned` |
| `-CodexPath` | `string` | *(tự dò)* | Đường dẫn thủ công tới `codex.exe` / `codex.cmd` nếu cài ở vị trí đặc biệt |
| `-Lane1Home` | `string` | `%USERPROFILE%\.codex` | Thư mục `CODEX_HOME` của Luồng 1 |
| `-Lane2Home` | `string` | `%USERPROFILE%\.codex-official` | Thư mục `CODEX_HOME` của Luồng 2 |
| `-LocalBin` | `string` | `%USERPROFILE%\.local\bin` | Thư mục lưu `codex.cmd`, `codex-official.cmd`, `codex-t3.cmd` |
| `-CargoTargetDir` | `string` | `%TEMP%\codex-lane2-target` | Thư mục build Cargo riêng cho Luồng 2 (đổi sang ổ khác nếu ổ `C:` ít dung lượng) |
| `-OfficialModel` | `string` | *(để trống)* | Đặt model mặc định cố định cho Luồng 2 (vd `gpt-6.2-sol`) |
| `-OfficialReasoning` | `string` | *(để trống)* | Đặt mức suy luận (`low`, `medium`, `high`, `ultra`) nếu muốn cố định |
| `-OfficialServiceTier` | `string` | *(để trống)* | Đặt `service_tier` (vd `priority`) nếu tài khoản của bạn có hỗ trợ |
| `-ApprovalPolicy` | `never` \| `on-request` | `never` | Chế độ tự chạy trong sandbox (`never`) hay hỏi duyệt từng lệnh (`on-request`) |
| `-AllowSandboxNetwork` | `switch` | `false` | Mặc định ngắt mạng trong shell sandbox (`network_access = false`) để cách ly phân tích tĩnh; bật cờ này nếu cần lệnh shell truy cập Internet |
| `-ConfigureGateway` | `switch` | `false` | Bật cấu hình cổng API bên thứ 3 cho Luồng 1 |
| `-GatewayProviderName` | `string` | `OpenAI` | Tên mục `[model_providers.<Name>]` cho Luồng 1 |
| `-GatewayBaseUrl` | `string` | *(trống)* | Base URL của cổng API bên thứ 3 (vd `https://example.com/v1`) |
| `-GatewayModel` | `string` | *(trống)* | Model mặc định cho Luồng 1 khi dùng `-ConfigureGateway` |
| `-GatewayApiKey` | `string` | *(trống)* | API key truyền lúc chạy (không lưu trong repo) |
| `-SyncSessions` | `switch` | `false` | Gọi `sync-sessions.py` để đồng bộ `session_index.jsonl`, `Pinned` và `Goals` |
| `-InstallBridgeTemplate` | `switch` | `false` | Tạo file mẫu `artifacts/dual-lane/DUAL_LANE_BRIDGE.md` trong `-RepoPath` |
| `-DryRun` | `switch` | `false` | Chạy kiểm tra thực tế và in kế hoạch mà **không sửa bất kỳ tệp nào trên đĩa** |

### 4.2. `scripts/sync-sessions.py`

| Tham số | Mặc định | Ý nghĩa |
| :--- | :--- | :--- |
| `--lane1` | `~/.codex` | Thư mục `CODEX_HOME` nguồn |
| `--lane2` | `~/.codex-official` | Thư mục `CODEX_HOME` đích |
| `--repo` | *(tùy chọn)* | Gán `cwd` cho các phiên `is_pinned = 1` để `codex resume` trong dự án hiện ngay |
| `--approval-mode` | *(giữ nguyên)* | Gán `never` hoặc `on-request` cho các phiên đồng bộ |
| `--dry-run` | `false` | Chỉ kiểm tra schema và đếm bản ghi, không ghi xuống SQLite/JSONL |

### 4.3. `scripts/doctor.ps1`

| Tham số | Mặc định | Ý nghĩa |
| :--- | :--- | :--- |
| `-Lane1Home` | `%USERPROFILE%\.codex` | Thư mục Luồng 1 cần kiểm tra |
| `-Lane2Home` | `%USERPROFILE%\.codex-official` | Thư mục Luồng 2 cần kiểm tra |
| `-LocalBin` | `%USERPROFILE%\.local\bin` | Thư mục launcher CLI cần kiểm tra |

---

## 5. Hướng dẫn Gỡ cài đặt / Hoàn tác an toàn 100%

> [!CAUTION]
> **Rất quan trọng khi gỡ trên Windows:** Các thư mục `memories`, `memories_v2`, `sessions`, `archived_sessions`, `skills`, `plugins` bên trong `~/.codex-official` là **NTFS Directory Junction** trỏ tới dữ liệu thật trong `~/.codex`.
> Hãy **gỡ từng Junction bằng `cmd /c rmdir` trước** khi xóa thư mục `~/.codex-official` để tuyệt đối không làm mất dữ liệu lịch sử gốc trong `~/.codex`!

```powershell
# 1. Gỡ an toàn 6 NTFS Junction (chỉ gỡ liên kết, giữ nguyên 100% dữ liệu gốc trong ~/.codex):
foreach ($d in @('memories','memories_v2','sessions','archived_sessions','skills','plugins')) {
    $p = Join-Path "$env:USERPROFILE\.codex-official" $d
    if (Test-Path -LiteralPath $p) { cmd /c rmdir "$p" }
}

# 2. Xóa phần còn lại của ~/.codex-official và 3 launcher CLI:
Remove-Item "$env:USERPROFILE\.codex-official" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\.local\bin\codex.cmd", `
            "$env:USERPROFILE\.local\bin\codex-official.cmd", `
            "$env:USERPROFILE\.local\bin\codex-t3.cmd" -Force -ErrorAction SilentlyContinue

# 3. (Nếu muốn khôi phục ~/.codex/config.toml về bản gốc trước khi chạy -ConfigureGateway):
if (Test-Path "$env:USERPROFILE\.codex\config.backup.toml") {
    Copy-Item "$env:USERPROFILE\.codex\config.backup.toml" "$env:USERPROFILE\.codex\config.toml" -Force
}
```
