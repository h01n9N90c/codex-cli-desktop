# Hướng dẫn Chi tiết & Khai báo Mã nguồn / Công cụ (Manifest)

> **Tác giả:** **Lê Hoàng Ngọc Tươi** | **Giấy phép:** Apache License 2.0 ([LICENSE](../LICENSE) · [NOTICE](../NOTICE))  
> Tài liệu này minh bạch hóa **100% từng tệp mã nguồn, từng hàm thực thi, tham số dòng lệnh, đường dẫn đọc/ghi và giới hạn tác động** trong bộ **Codex Dual-Lane & Security Kit**, để bất kỳ lập trình viên hay đội kiểm duyệt an ninh nào cũng có thể kiểm chứng trước khi chạy.

---

## 1. Cam kết minh bạch an ninh (Những gì bộ công cụ TUYỆT ĐỐI KHÔNG làm)

* **Không kết nối Internet / không tải mã từ xa:** Toàn bộ script chạy cục bộ 100% trên máy của bạn; không gọi `Invoke-WebRequest`, `curl`, `wget` hay gửi telemetry ra ngoài.
* **Không đòi quyền Administrator bắt buộc:** Mọi thao tác (`Get-AppxPackage`, tạo NTFS Directory Junction trong `%USERPROFILE%`, sửa `User PATH`, đọc/ghi `~/.codex*`) đều chạy ở quyền người dùng thường.
* **Không chứa API key, token hay mock data:** Mọi thông số máy (phiên bản OS, ổ đĩa, NTFS, dung lượng trống, đường dẫn `codex`, danh sách feature flags, bảng cột SQLite) đều được đọc trực tiếp từ hệ thống thật tại thời điểm chạy.
* **Không xóa đè cấu hình gốc không sao lưu:** Mọi tệp cấu hình/rule/`AGENTS.md` cũ đều được sao lưu với hậu tố `.backup-yyyyMMdd-HHmmss` (kèm bản kiểm chứng SHA-256 trong `.rollback/latest.json` trên Windows hoặc `.rollback/latest.tsv` trên Unix) trước khi ghi.
* **Không sửa trạng thái nội bộ sandbox của Codex:** Không tự ý thay đổi `.sandbox\deny_read_acl_state.json` hay tệp runtime riêng của Codex.

---

## 2. Khai báo chi tiết toàn bộ tệp mã nguồn & công cụ

### 2.1. Công cụ thực thi (`scripts/`)

| Tệp | Ngôn ngữ / Runtime | Vai trò chính | Đường dẫn ĐỌC | Đường dẫn GHI |
| :--- | :--- | :--- | :--- | :--- |
| [`scripts/setup-dual-lane.ps1`](../scripts/setup-dual-lane.ps1) | PowerShell 5.1+ / 7+ (Windows) | Bộ cài đặt chính 1 chạm cho Windows (hỗ trợ `-DryRun`/`-WhatIf`, alias `-ProjectRoot`, TOML merge không phá hủy + ghi nguyên tử, kiểm tra fail-closed chống plaintext secret, khóa ACL `icacls` 2 bước, snapshot SHA-256) | `Get-AppxPackage OpenAI.Codex`, `PATH`, `Get-Volume`, `codex features list`, `templates/*`, `config.toml` cũ | `~/.codex-official/config.toml`, `~/.codex*/rules/default.rules`, `~/.codex*/AGENTS.md`, `~/.codex-official/.rollback/latest.json`, 6 NTFS Junctions, 3 wrapper `.cmd` trong `~/.local/bin/` |
| [`scripts/setup-dual-lane.sh`](../scripts/setup-dual-lane.sh) | Bash (`set -euo pipefail`, macOS / Linux / WSL) | Bộ cài đặt tương đương cho hệ Unix (hỗ trợ `--dry-run`, `umask 077` / `chmod 700` / `chmod 600`, ghi nguyên tử `mktemp`, TOML merge giữ khóa top-level & section, manifest SHA-256 `.rollback/latest.tsv`, `--install-bridge`, `--sync-sessions`, `--use-git-worktree`) | `type -ap codex`, `codex features list`, `templates/*`, `config.toml` cũ | `~/.codex-official/config.toml`, `~/.codex-official/.rollback/latest.tsv`, 6 symlinks (`ln -s`), `rules/default.rules`, `AGENTS.md`, 3 wrapper shell trong `~/.local/bin/` |
| [`scripts/restore-original.ps1`](../scripts/restore-original.ps1) | PowerShell 5.1+ / 7+ (Windows) | **Khôi phục chính xác 1 chạm** về trạng thái gốc dựa trên manifest `.rollback/latest.json` với preflight kiểm chứng **SHA-256**, khóa phạm vi đường dẫn phía caller & chặn reparse point (hỗ trợ `-DryRun`/`-WhatIf`, `-SnapshotPath`, `-RemoveLane2Home`) | `~/.codex-official/.rollback/latest.json`, các bản `.backup-*`, mã băm SHA-256 | Tháo an toàn 6 NTFS Junction bằng Win32 `Directory.Delete` trước, hoàn trả nguyên tử byte-exact từng tệp cấu hình cũ (giữ bản sao lưu nếu tệp đang bị khóa), gỡ 3 wrapper `.cmd` và làm sạch `PATH` |
| [`scripts/restore-original.sh`](../scripts/restore-original.sh) | Bash (`set -euo pipefail`, macOS / Linux / WSL) | Công cụ khôi phục chính xác tương đương cho macOS / Linux / WSL (hỗ trợ `--snapshot PATH`, `--dry-run`, `--remove-lane2-home`, preflight kiểm chứng manifest `.rollback/latest.tsv` + SHA-256 & chặn symlink/path traversal) | `~/.codex-official/.rollback/latest.tsv`, các bản `.backup-*` và symlink trong `~/.codex-official` | Tháo an toàn 6 symlink trước, hoàn trả byte-exact từng tệp qua staging `mktemp` nguyên tử và gỡ 3 wrapper CLI |
| [`scripts/doctor.ps1`](../scripts/doctor.ps1) | PowerShell 5.1+ / 7+ (Windows) | Kiểm tra sức khỏe, tương thích hệ thống, thứ tự `PATH`, 6/6 đích Junction, 7 probe `execpolicy`, quét plaintext secret, kiểm tra NTFS Allow-ACE `CodexSandboxUsers` & kiểm tra tham khảo chỉ-đọc `.sandbox\deny_read_acl_state.json` (**Chỉ đọc — Read-Only**) | `OSVersion`, `Get-Volume`, `Get-Command codex/codex-t3/python`, đích Junction, `default.rules`/`AGENTS.md`/`config.toml`, `Get-Acl`, `.sandbox\deny_read_acl_state.json` *(chỉ đọc trạng thái)*, `auth.json` *(chỉ đọc `auth_mode` đã lọc, không in token/key)* | **Không ghi bất kỳ tệp nào** |
| [`scripts/doctor.sh`](../scripts/doctor.sh) | Bash (`set -euo pipefail`, macOS / Linux / WSL) | Phiên bản chẩn đoán hệ thống, kiểm tra quyền POSIX `0600`, rò rỉ plaintext `api_key =` & 5 probe thực thi `execpolicy` tương đương cho Unix (**Chỉ đọc — Read-Only**) | `uname`, `df`, `command -v codex/codex-t3/python3`, 6 symlinks, `default.rules`/`AGENTS.md`/`config.toml`, quyền POSIX (`stat`), trường `auth_mode` trong `auth.json` | **Không ghi bất kỳ tệp nào** |
| [`scripts/sync-sessions.py`](../scripts/sync-sessions.py) | Python 3.8+ (thư viện chuẩn `sqlite3`, `json`, `os`, `re`, `pathlib`, `tempfile`) | Đồng bộ tên phiên, mục đã ghim (`Pinned`) & `Goals` từ Luồng 1 (mở **chỉ-đọc `?mode=ro` + `PRAGMA query_only=ON`**) sang Luồng 2 bằng SQL tham số hóa + allowlist bảng/cột, chống symlink/path-traversal sidecar & ghi JSONL nguyên tử `0600` (hỗ trợ `--pinned-only`, `--dry-run`) | `~/.codex/session_index.jsonl`, `~/.codex/state_*.sqlite` *(read-only URI + `PRAGMA quick_check(1)`)*, `~/.codex/goals_*.sqlite` *(read-only URI)*, `PRAGMA table_info(...)` | `~/.codex-official/session_index.jsonl` *(temp `0600` + `fsync` + `os.replace`)*, `~/.codex-official/state_*.sqlite`, `~/.codex-official/goals_*.sqlite` *(kèm `PRAGMA wal_checkpoint(TRUNCATE)`)* |

### 2.2. Tệp mẫu chính sách & phối hợp (`templates/`)

| Tệp | Mục đích & Hành vi thực thi |
| :--- | :--- |
| [`templates/default.rules`](../templates/default.rules) | Bộ luật **Execpolicy (Starlark)** nạp vào tầng Rust của Codex (có chú thích chi tiết từng nhóm lệnh & cách tùy biến an toàn): chặn cứng (`forbidden`) nhóm lệnh phá hệ thống/ransomware (`vssadmin`, `bcdedit`, `wbadmin`, `diskpart`, `format`), cài persistence/Registry (`schtasks`, `sc`, `reg add/delete/import`), phá NTFS ACL/mạng (`icacls`, `takeown`, `net`, `net1`, `netsh`), xóa lịch sử Git (`git push --force/-f`), trình thông dịch corpus & Windows LOLBins để ép phân tích tĩnh (`php`, `ruby`, `perl`, `cscript`, `wscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `msiexec`, `wmic`, `Start-Process`/`start-process`/`saps`, `Invoke-Expression`/`invoke-expression`/`iex`/`IEX`), kèm biến thể `.exe`/`.com`; và bắt buộc hỏi xác nhận (`prompt`) với `git push`, `git reset --hard`, `git clean`. |
| [`templates/AGENTS.lane1.md`](../templates/AGENTS.lane1.md) | Chỉ thị toàn cục cài vào `~/.codex/AGENTS.md` cho **Luồng 1**: chống Prompt Injection, **cách ly chỉ phân tích tĩnh (`Static-Analysis-Only` — phân định rõ hành vi bị cấm vs. được phép)**, cấm đọc/in `config.toml`/`auth.json`/`.rollback/`/`.env`/`.ssh/`, giữ kỷ luật artifact và tuân thủ phân vùng trong `DUAL_LANE_BRIDGE.md`. Có chú thích rõ phần bắt buộc giữ nguyên vs. phần được phép tùy biến. |
| [`templates/AGENTS.lane2.md`](../templates/AGENTS.lane2.md) | Chỉ thị toàn cục cài vào `~/.codex-official/AGENTS.md` cho **Luồng 2**: cùng chuẩn bảo vệ & cách ly phân tích tĩnh với Luồng 1, bổ sung luật **Zero-Collision** (không sửa vùng tệp/catalog của Luồng 1, dùng `CARGO_TARGET_DIR` riêng, đọc chéo handoff của Luồng 1). |
| [`templates/DUAL_LANE_BRIDGE.md`](../templates/DUAL_LANE_BRIDGE.md) | Tệp cầu nối mẫu để chép vào dự án của bạn (`artifacts/dual-lane/DUAL_LANE_BRIDGE.md`), kèm hướng dẫn rõ mục nào cần điền, quy tắc an toàn nào phải giữ nguyên, và lưu ý ranh giới mềm vs. cứng (`-UseGitWorktree` / `--use-git-worktree`). |

### 2.3. Tài liệu & cấu hình repo (`docs/`, gốc repo)

| Tệp | Nội dung |
| :--- | :--- |
| [`README.md`](../README.md) | Trang tổng quan, bảng chọn kịch bản theo nhu cầu, ranh giới bảo mật minh bạch, sơ đồ kiến trúc và lệnh cài nhanh 3 bước. |
| [`docs/GUIDE_AND_MANIFEST.md`](./GUIDE_AND_MANIFEST.md) | Chính tài liệu bạn đang đọc — khai báo chi tiết mã nguồn, hàm, bảng tham số đầy đủ và hướng dẫn gỡ bỏ an toàn. |
| [`docs/REAL_CODEX_CHECKLIST.md`](./REAL_CODEX_CHECKLIST.md) | Danh sách lệnh kiểm chứng thực nghiệm trước & sau khi cài đặt (0 plaintext key, behavioral `execpolicy check`, kiểm tra ACL/chmod, merge TOML, UPSERT SQLite và rollback `-DryRun`). |
| [`docs/SECURITY_MODEL.md`](./SECURITY_MODEL.md) | Phân tích sâu 4 lớp phòng thủ, bảng minh bạch Bộ Kit vs. Giới hạn OS/Codex runtime (bao gồm kế thừa `CodexSandboxUsers`, atomic replace reset DACL, `keyring` + `env_key`), ranh giới Mềm vs. Cứng và Khiên Git. |
| [`docs/TROUBLESHOOTING.md`](./TROUBLESHOOTING.md) | Hướng dẫn khắc phục 9 lỗi thực chiến thường gặp (bao gồm cảnh báo Defender trên `.jsonl`, reset `kernel_acl` sau `codex features` và gỡ bỏ an toàn không mất phiên). |
| [`tests/test_sync_sessions.py`](../tests/test_sync_sessions.py) | Bộ Unit Test Python (`unittest`) kiểm chứng đọc nguồn `?mode=ro`, UPSERT (`INSERT` + `UPDATE`), atomic JSONL, `--pinned-only`, lệch schema, path-traversal/symlink và `--dry-run`. |
| [`tests/test-kit.ps1`](../tests/test-kit.ps1) | Bộ Test PowerShell kiểm chứng AST, `-DryRun`, merge `config.toml` không phá hủy, mặc định `on-request`, cô lập `env_key`, UTF-8 không BOM, chống path-traversal và khôi phục SHA-256. |
| [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | Pipeline GitHub Actions CI tự động chạy toàn bộ kiểm tra cú pháp, unit test, smoke test, line-ending và quét rò rỉ bí mật. |
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
5. **Chuẩn bị thư mục:** Tạo `~/.codex`, `~/.codex/rules`, `~/.codex-official`, `~/.codex-official/rules`, `~/.local/bin` nếu chưa tồn tại.
6. **Tạo 6 NTFS Directory Junction:** Nối `memories`, `memories_v2`, `sessions`, `archived_sessions`, `skills`, `plugins` từ `~/.codex-official` sang `~/.codex` (giữ nguyên nếu đã là Junction; sao lưu thư mục cũ trước khi tạo nếu có xung đột).
7. **Cài đặt tường lửa lệnh (`rules/default.rules`):** Sao lưu bản cũ kèm SHA-256 rồi cài vào cả 2 luồng.
8. **Cài đặt `AGENTS.md` toàn cục:** Sao lưu bản cũ rồi cài `AGENTS.lane1.md` vào `~/.codex/AGENTS.md`, `AGENTS.lane2.md` vào `~/.codex-official/AGENTS.md`.
9. **Hợp nhất không phá hủy `~/.codex-official/config.toml` (Luồng 2 Chính chủ):** Giữ nguyên toàn bộ `[projects.*]` đã `trusted` và các section tùy biến (`[mcp_servers.*]`, `[tui]`, `[plugins.*]`), escape chuỗi TOML, đặt `sandbox_mode = "workspace-write"`, `approval_policy = "$ApprovalPolicy"`, `network_access = false` (trừ khi bật `-AllowSandboxNetwork`), `daemon_auto_start = false` (khi hỗ trợ), lọc biến môi trường nhạy cảm và tách `CARGO_TARGET_DIR`.
10. ***(Tùy chọn `-ConfigureGateway`)* Cấu hình cổng API bên thứ 3 cho Luồng 1:** Chỉ cần `-ConfigureGateway` và `-GatewayBaseUrl`; khuyến nghị nhập key ẩn qua `-PromptGatewayApiKey` hoặc đặt trước biến môi trường `-GatewayApiKeyEnv` (sử dụng `env_key`, **không bao giờ ghi plaintext key** vào `config.toml` hay `.backup-*`). Lưu bản sạch `~/.codex/config.backup.toml` (nếu chưa có).
11. **Tạo 3 launcher CLI trong `~/.local/bin/`:** `codex.cmd`, `codex-official.cmd`, `codex-t3.cmd` (escape `%` bằng `Escape-CmdSetValue`, tự thêm `chcp 65001 >nul` khi đường dẫn có Unicode, tự dò lại gói `WindowsApps` khi Microsoft Store cập nhật), đồng thời đưa `~/.local/bin` lên đầu User `PATH` (trừ khi truyền `-SkipPathUpdate`).
12. ***(Tùy chọn `-InstallBridgeTemplate`)* Chép mẫu `DUAL_LANE_BRIDGE.md`:** Tạo `<RepoPath>\artifacts\dual-lane\DUAL_LANE_BRIDGE.md` nếu chưa tồn tại (không ghi đè tệp đã có).
13. **Lưu Manifest SHA-256, khóa ACL 2 bước & *(Tùy chọn `-SyncSessions`)* Đồng bộ phiên:** Lưu `~/.codex-official/.rollback/latest.json` + `snapshot-<timestamp>.json` trước khi đồng bộ, chạy `Protect-SensitiveFileAcl` (`icacls /inheritance:d` rồi `/remove:g "CodexSandboxUsers"` khi nhóm tồn tại) lên `auth.json`, `config.toml`, bản sao lưu và manifest rollback, chạy `scripts/sync-sessions.py` (nếu bật `-SyncSessions` và có Python 3 thật, bỏ qua stub `WindowsApps`), sau đó kiểm chứng `codex.cmd --version`.

### 3.2. Bản đồ Chi tiết Các Hàm Chính

#### `scripts/setup-dual-lane.ps1` (PowerShell 5.1+ / 7+)
| Tên hàm | Đầu vào | Thực hiện chính xác điều gì |
| :--- | :--- | :--- |
| `Write-Step` | `Message` | In tiêu đề từng bước cài đặt có màu sắc rõ ràng trên Console. |
| `Escape-TomlBasicString` | `Value` | Escape ký tự `\`, `"` và ký tự điều khiển thành chuỗi TOML hợp lệ (an toàn với đường dẫn có dấu cách, Unicode, `&`). |
| `Escape-CmdSetValue` | `Value`, `Label` | Xác thực chống ký tự điều khiển và escape `%` $\rightarrow$ `%%` cho `set "..."` trong `.cmd` wrapper (an toàn với đường dẫn chứa `100%`, `&`, `!`, dấu cách và Unicode). |
| `Write-Utf8NoBom` | `FilePath`, `Text` | Ghi tệp `config.toml`, `.cmd` và manifest JSON theo chuẩn **UTF-8 không BOM** bằng cơ chế **nguyên tử** (ghi tệp tạm cùng thư mục rồi `File.Replace`/`Move`) để tránh hỏng tệp khi bị ngắt giữa chừng. |
| `Assert-NoPlaintextSecretInToml` | `TomlContent`, `ContextLabel`, `ForbiddenLiteralSecret` | Cổng chặn fail-closed trước khi ghi `config.toml`: từ chối ghi đĩa nếu phát hiện `experimental_bearer_token`, plaintext `api_key`, hoặc chuỗi secret vừa nhập. |
| `Assert-SafeGitBranchName` | `BranchName` | Xác thực tên nhánh `-Lane2Branch` chống tiêm tham số Git (`-`) và ký tự cấm trước khi Bước 4 gọi `git check-ref-format` và tạo worktree. |
| `Protect-SensitiveFileAcl` | `FilePath` | Từ chối reparse point, chạy **2 lệnh `icacls.exe` tuần tự**: (1) `icacls <file> /inheritance:d` để tắt kế thừa từ `~/.codex*` và chuyển ACE kế thừa thành tường minh, rồi kiểm tra sự tồn tại của `CodexSandboxUsers` qua `NTAccount.Translate` + `Get-Acl` và chỉ chạy (2) `icacls <file> /remove:g "CodexSandboxUsers"` khi nhóm có mặt (bỏ qua êm ái trên máy mới chưa có nhóm này, không đụng tới Deny ACE bảo vệ). *(Lưu ý: atomic replace của Codex khi sửa `config.toml`/`auth.json` sẽ reset DACL — xem [SECURITY_MODEL.md](SECURITY_MODEL.md)).* |
| `Backup-IfExists` | `FilePath` | Tính mã băm SHA-256 bản gốc, sao lưu sang `<FilePath>.backup-yyyyMMdd-HHmmss`, khóa ACL bản sao lưu và ghi nhận vào manifest rollback (tôn trọng `-DryRun` / `-WhatIf`). |
| `Resolve-CodexExecutable` | `ExplicitPath`, `ExcludedDir` | Tự dò đường dẫn thật của `codex.exe`/`codex.cmd` theo 4 nguồn: `-CodexPath` $\rightarrow$ `WindowsApps` (`OpenAI.Codex`) $\rightarrow$ `PATH` *(loại trừ `~/.local/bin`)* $\rightarrow$ `%APPDATA%\npm` & `%LOCALAPPDATA%\Programs`. |
| `Get-SupportedCodexFeatures` | `ExePath`, `ProbeHome` | Chạy `& $ExePath features list` trong `CODEX_HOME` tạm cô lập để lấy danh sách feature flags thật mà bản Codex trên máy hỗ trợ. |
| `Get-ExistingTrustedProjects` | `ConfigPaths[]` | Quét các `config.toml` cũ của cả Luồng 1 & Luồng 2 (đọc tường minh `-Encoding UTF8`) để giữ nguyên 100% danh sách `[projects.'...']` / `[projects."..."]` đã đánh dấu `trusted`. |
| `Merge-CodexConfigToml` | `ExistingPath`, `ManagedTopBlock`, `ManagedSectionsBlock`, `ManagedTopKeys[]`, `ManagedSectionNames[]` | Hợp nhất không phá hủy vào `config.toml` hiện có: giữ nguyên mọi khóa top-level (kể cả mảng/bảng nhiều dòng), comment `#` sau header section, `[[array_of_tables]]` và section tùy chỉnh (`[mcp_servers.*]`, `[tui]`, `[plugins.*]`), loại bỏ `experimental_bearer_token` cũ và chỉ cập nhật phần do Dual-Lane quản lý. |

#### `scripts/doctor.ps1` (PowerShell 5.1+ / 7+ — Chỉ đọc)
| Thành phần / Mục kiểm tra | Thực hiện chính xác điều gì |
| :--- | :--- |
| `Report` | Định dạng và thống kê 3 trạng thái `[PASS]` / `[WARN]` / `[FAIL]`; thoát mã `1` nếu có `[FAIL]` (vd ổ không phải NTFS, phát hiện plaintext secret trong `config.toml`, hoặc lệnh bắt buộc cấm lại bị `execpolicy` cho phép), mã `0` nếu không có `[FAIL]`. |
| 8 nhóm kiểm tra thật (Read-Only) | (1) OS & PowerShell; (2) Toàn bộ ổ đĩa cố định, NTFS & dung lượng trống thật; (3) Thứ tự `PATH` & phiên bản `codex` / `codex-t3`; (4) Tình trạng & đích trỏ thật của 6/6 NTFS Directory Junction; (5) Đầy đủ `config.toml` + `default.rules` + `AGENTS.md`, trạng thái `Static-Analysis-Only`, `sandbox_net=restricted/enabled`, `[shell_environment_policy]` & **7 live probe `codex execpolicy check`** (`php`, `mshta`, `vssadmin`, `icacls`, `git push --force`, `Start-Process`, `iex`); (6) Quét `config.toml` trong bộ nhớ chống plaintext `experimental_bearer_token` / `api_key` *(tuyệt đối không in giá trị secret)*; (7) Cách ly `auth.json` *(chỉ đọc `auth_mode` đã lọc theo allowlist)*, kiểm tra **Allow ACE** của `CodexSandboxUsers` (không báo nhầm trên Deny ACE bảo vệ) + `AreAccessRulesProtected`, và kiểm tra tham khảo chỉ-đọc `.sandbox\deny_read_acl_state.json` nếu có (không sửa và không in nội dung); (8) Tình trạng Python 3 thật cho `sync-sessions.py`. |

#### `scripts/sync-sessions.py` (Python 3.8+ — Chỉ dùng thư viện chuẩn)
| Tên hàm | Đầu vào | Thực hiện chính xác điều gì |
| :--- | :--- | :--- |
| `connect_readonly` | `db_path`, `timeout` | Mở tệp SQLite nguồn của Luồng 1 (và DB đích khi `--dry-run`) ở chế độ chỉ-đọc (`file:...?mode=ro` + `PRAGMA query_only=ON`, `PRAGMA busy_timeout`) để tuyệt đối không chiếm khóa ghi khi Luồng 1 đang chạy. |
| `ensure_contained_path` | `base_dir`, `candidate` | Chặn path-traversal (`..`) và symlink trỏ ra ngoài thư mục Codex gốc (bao gồm cả tệp sidecar `-wal`/`-shm`/`-journal`). |
| `find_latest_versioned_db` | `directory`, `prefix` | Tự dò tệp SQLite phiên bản mới nhất (`state_*.sqlite`, `goals_*.sqlite`) bằng `os.scandir` (an toàn với đường dẫn chứa ký tự `[` `]`). |
| `get_tables` / `get_columns` / `get_column_info` | `conn`, `table` | Kiểm tra allowlist bảng (`ALLOWED_TABLES`), xác thực tên cột (`validate_sql_identifier`/`quote_identifier`), truy vấn `sqlite_master` và `PRAGMA table_info(...)` để tương thích động mọi phiên bản schema và chặn second-order SQLi. |
| `sync_session_index` / `atomic_write_text` | `lane1`, `lane2`, `dry_run`, `allowed_ids` | Hợp nhất không trùng lặp các bản ghi theo `id` giữa 2 tệp `session_index.jsonl` (hỗ trợ `--pinned-only`), ghi nguyên tử qua `NamedTemporaryFile` + `0o600` (POSIX) + `fsync` + `os.replace`. |
| `copy_shared_table` | `c1`, `c2`, `table`, `dry_run` | Chỉ sao chép phần giao các cột tồn tại ở cả 2 DB (`INSERT OR REPLACE`) bằng SQL tham số hóa (`?`), tránh lỗi lệch schema. |
| `sync_state_db` | `lane1`, `lane2`, `repo_path`, `approval_mode`, `pinned_only`, `dry_run` | Kiểm tra toàn vẹn nguồn (`PRAGMA quick_check(1)`) và nạp dữ liệu trước khi mở transaction ghi (`BEGIN IMMEDIATE`), thực hiện **UPSERT (`INSERT` dòng thiếu + `UPDATE` dòng đã có)** cho `threads` cùng `thread_sections`, `projects`, `project_roots`, tự xử lý an toàn khi DB bị khóa/hỏng mà không làm hư DB đích, và chạy `PRAGMA wal_checkpoint(TRUNCATE)`. |
| `sync_goals_db` | `lane1`, `lane2`, `dry_run` | Đồng bộ bảng `thread_goals` và `thread_goal_continuation_deferrals`, kèm `PRAGMA wal_checkpoint(TRUNCATE)`. |

#### `scripts/setup-dual-lane.sh`, `scripts/doctor.sh`, `scripts/restore-original.sh` (Bash — macOS / Linux / WSL)
* `setup-dual-lane.sh`: Chạy với `set -euo pipefail`, `umask 077`, `chmod 700` trên thư mục Codex/`.rollback` và `chmod 600` trên `config.toml`/`auth.json`/bản sao lưu/manifest, ghi tệp nguyên tử qua `mktemp` + `trap` dọn tệp tạm, từ chối ghi đè symlink, merge không phá hủy cả top-level key lẫn `[section]` của `config.toml`, sinh 3 wrapper với `shell_quote()` chống metacharacter injection, và ghi manifest SHA-256 tại `~/.codex-official/.rollback/latest.tsv`.
* `doctor.sh`: Chạy chỉ-đọc (`set -euo pipefail`, `umask 077`), kiểm tra 6 symlink không gãy/lệch đích, kiểm tra `[sandbox_workspace_write] network_access = false`, cảnh báo nếu phát hiện plaintext `api_key =` (không in giá trị), chạy **5 live probe `codex execpolicy check`** (`php`, `mshta`, `vssadmin`, `Start-Process`, `iex`), kiểm tra quyền POSIX `0600` và chỉ in `auth_mode` đã lọc theo allowlist.
* `restore-original.sh`: Chạy preflight xác thực manifest `.rollback/latest.tsv` (hoặc `--snapshot PATH`) trước khi đụng đĩa, chặn symlink/path traversal 5 lớp (`assert_safe_contained_path`), kiểm chứng SHA-256 (`sha256sum`/`shasum -a 256`/`openssl dgst -sha256`) trước/trong/sau khi staging nguyên tử, tháo sạch 6 symlink trước và kiểm chứng `find -type l` rỗng trước khi `--remove-lane2-home`.

---

## 4. Bảng tham số dòng lệnh đầy đủ

### 4.1. `scripts/setup-dual-lane.ps1` (Windows)

| Tham số | Kiểu | Mặc định | Ý nghĩa |
| :--- | :--- | :--- | :--- |
| `-RepoPath` *(alias: `-ProjectRoot`)* | `string` | Thư mục hiện tại | Đường dẫn dự án muốn đánh dấu `trusted` và (tùy chọn) gắn cầu nối/đồng bộ `Pinned` |
| `-CodexPath` | `string` | *(tự dò)* | Đường dẫn thủ công tới `codex.exe` / `codex.cmd` nếu cài ở vị trí đặc biệt |
| `-Lane1Home` | `string` | `%USERPROFILE%\.codex` | Thư mục `CODEX_HOME` của Luồng 1 |
| `-Lane2Home` | `string` | `%USERPROFILE%\.codex-official` | Thư mục `CODEX_HOME` của Luồng 2 |
| `-LocalBin` | `string` | `%USERPROFILE%\.local\bin` | Thư mục lưu `codex.cmd`, `codex-official.cmd`, `codex-t3.cmd` |
| `-CargoTargetDir` | `string` | `%TEMP%\codex-lane2-target` | Thư mục build Cargo riêng cho Luồng 2 (đổi sang ổ khác nếu ổ `C:` ít dung lượng) |
| `-OfficialModel` | `string` | *(để trống)* | Đặt model mặc định cố định cho Luồng 2 (vd `<model-slug>` được tài khoản hỗ trợ) |
| `-OfficialReasoning` | `string` | *(để trống)* | Đặt mức suy luận (`low`, `medium`, `high`, `ultra`) nếu muốn cố định |
| `-OfficialServiceTier` | `string` | *(để trống)* | Đặt `service_tier` nếu tài khoản của bạn hỗ trợ |
| `-ApprovalPolicy` | `on-request` \| `never` | `on-request` | Mặc định an toàn (`on-request`); chỉ truyền `never` khi chạy tự động đã cô lập |
| `-AllowSandboxNetwork` | `switch` | `false` | Mặc định ngắt mạng trong shell sandbox (`network_access = false`); bật cờ này nếu cần lệnh shell truy cập Internet |
| `-UseGitWorktree` | `switch` | `false` | Tự động tạo Git worktree riêng (`<RepoPath>-lane2`) cho Luồng 2 để cưỡng chế phân quyền ghi ở cấp OS Sandbox |
| `-Lane2WorktreePath` | `string` | `<RepoPath>-lane2` | Đường dẫn tùy chỉnh cho Git worktree của Luồng 2 khi bật `-UseGitWorktree` |
| `-Lane2Branch` | `string` | `dual-lane-2` | Tên nhánh Git dùng cho worktree của Luồng 2 khi bật `-UseGitWorktree` |
| `-ConfigureGateway` | `switch` | `false` | Bật cấu hình cổng API bên thứ 3 cho Luồng 1 (sử dụng `env_key`, không lưu plaintext key trong `config.toml`) |
| `-GatewayProviderName` | `string` | `OpenAI` | Tên mục `[model_providers.<Name>]` cho Luồng 1 |
| `-GatewayBaseUrl` | `string` | *(trống)* | Base URL của cổng API bên thứ 3 (bắt buộc khi truyền `-ConfigureGateway`) |
| `-GatewayModel` | `string` | *(trống)* | Model mặc định cho Luồng 1 khi dùng `-ConfigureGateway` |
| `-GatewayApiKeyEnv` | `string` | `CODEX_GATEWAY_API_KEY` | Tên biến môi trường lưu API key cho thuộc tính `env_key` của Codex |
| `-PromptGatewayApiKey` | `switch` | `false` | Nhập ẩn API key lúc chạy qua `Read-Host -AsSecureString` rồi lưu vào biến môi trường User `-GatewayApiKeyEnv` |
| `-GatewayApiKey` | `string` | *(trống)* | *(Tương thích ngược — hạn chế dùng để tránh lưu trong lịch sử PowerShell)* Lưu key vào biến môi trường User `-GatewayApiKeyEnv`, không ghi vào `config.toml` |
| `-SyncSessions` | `switch` | `false` | Gọi `sync-sessions.py` để đồng bộ UPSERT `session_index.jsonl`, `Pinned` và `Goals` |
| `-PinnedOnlySync` | `switch` | `false` | Khi dùng cùng `-SyncSessions`, chỉ đồng bộ các phiên đã ghim (`Pinned`) |
| `-InstallBridgeTemplate` | `switch` | `false` | Tạo tệp mẫu `artifacts/dual-lane/DUAL_LANE_BRIDGE.md` trong `-RepoPath` |
| `-SkipPathUpdate` | `switch` | `false` | Bỏ qua bước tự sửa biến môi trường User `PATH` |
| `-DryRun` *(hoặc `-WhatIf`)* | `switch` | `false` | Chạy kiểm tra thực tế và in kế hoạch mà **không sửa bất kỳ tệp hay biến môi trường nào** |

### 4.2. `scripts/restore-original.ps1` (Windows)

| Tham số | Kiểu | Mặc định | Ý nghĩa |
| :--- | :--- | :--- | :--- |
| `-Lane1Home` | `string` | `%USERPROFILE%\.codex` | Thư mục Luồng 1 được caller ủy quyền *(manifest không được phép mở rộng phạm vi ra ngoài)* |
| `-Lane2Home` | `string` | `%USERPROFILE%\.codex-official` | Thư mục Luồng 2 được caller ủy quyền |
| `-LocalBin` | `string` | `%USERPROFILE%\.local\bin` | Thư mục chứa 3 wrapper `.cmd` cần gỡ |
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
| `--repo PATH` *(hoặc đối số vị trí `REPO_PATH`)* | Thư mục hiện tại | Đường dẫn dự án muốn đánh dấu `trusted` |
| `--approval-policy MODE` *(hoặc `CODEX_APPROVAL_POLICY`)* | `on-request` | `on-request` (mặc định an toàn) hoặc `never` |
| `--allow-sandbox-network` *(hoặc `CODEX_SANDBOX_NETWORK=true`)* | `false` | Bật `network_access = true` trong `[sandbox_workspace_write]` |
| `--use-git-worktree` | tắt | Tạo Git worktree riêng (`<repo>-lane2`) cho Luồng 2 |
| `--worktree-path PATH` | `<repo>-lane2` | Đường dẫn tùy chỉnh cho worktree Luồng 2 |
| `--install-bridge` | tắt | Chép `templates/DUAL_LANE_BRIDGE.md` vào `<repo>/artifacts/dual-lane/` |
| `--sync-sessions` | tắt | Chạy `scripts/sync-sessions.py` sau khi cài |
| `--pinned-only` | tắt | Đi cùng `--sync-sessions`, chỉ đồng bộ các phiên đã ghim |
| `--dry-run` | tắt | Xem trước mọi bước mà không ghi tệp nào lên đĩa |
| `CODEX_LANE1_HOME`, `CODEX_LANE2_HOME`, `CODEX_LOCAL_BIN`, `CODEX_CARGO_TARGET_DIR`, `CODEX_LANE2_BRANCH` | `~/.codex`, `~/.codex-official`, `~/.local/bin`, `${TMPDIR:-/tmp}/codex-lane2-target`, `dual-lane-2` | Biến môi trường ghi đè đường dẫn mặc định và tên nhánh worktree trên Unix |

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

### 4.6. `scripts/sync-sessions.py` (Đa nền tảng)

| Tham số | Mặc định | Ý nghĩa |
| :--- | :--- | :--- |
| `--lane1` | `~/.codex` | Thư mục `CODEX_HOME` nguồn (mở SQLite ở chế độ `?mode=ro`) |
| `--lane2` | `~/.codex-official` | Thư mục `CODEX_HOME` đích |
| `--repo` | *(tùy chọn)* | Gán `cwd` cho các phiên `is_pinned = 1` để `codex resume` trong dự án hiện ngay |
| `--approval-mode` | *(giữ nguyên)* | Gán `never` hoặc `on-request` cho các phiên đồng bộ |
| `--pinned-only` | `false` | Chỉ đồng bộ các phiên đã ghim (`is_pinned = 1` hoặc thuộc section), không kéo phiên chưa ghim |
| `--dry-run` | `false` | Chỉ kiểm tra schema và đếm bản ghi, không ghi xuống SQLite/JSONL |

---

## 5. Cơ chế Khôi phục Chính xác 1 Chạm (Deterministic SHA-256 Rollback)

Mỗi khi chạy `setup-dual-lane.ps1` (Windows) hoặc `setup-dual-lane.sh` (macOS / Linux / WSL), bộ cài tự động tính mã băm **SHA-256** của từng tệp cấu hình gốc trước khi sửa và ghi vào manifest giao dịch `~/.codex-official/.rollback/latest.json` (Windows) hoặc `~/.codex-official/.rollback/latest.tsv` (Unix), kèm bản lịch sử `snapshot-yyyyMMdd-HHmmss.*`.

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
