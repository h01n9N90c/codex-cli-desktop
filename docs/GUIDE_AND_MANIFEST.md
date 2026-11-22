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
| [`scripts/setup-dual-lane.ps1`](../scripts/setup-dual-lane.ps1) | PowerShell 5.1+ / 7+ (Windows) | Bộ cài đặt chính 1 chạm cho Windows (hỗ trợ `-DryRun`/`-WhatIf`, `-ReapplyAclOnly`, alias `-ProjectRoot` & đường dẫn tương đối `-RepoPath .`, chuẩn hóa đường dẫn dài 8.3 qua `GetLongPathNameW`, kế thừa chỉ-đọc `[projects."..."]` từ `~/.codex/config.toml` + tùy chọn `-ShareAuthToLane2`, TOML merge không phá hủy + ghi nguyên tử, cấu hình 1 cờ `-ConfigureCliGateway` / `-CliApiKeyEnv`, kiểm tra fail-closed chống plaintext secret, khóa ACL `icacls` 2 bước, wrapper worktree fail-closed cứng, nhật ký rollback tăng dần SHA-256) | `Get-AppxPackage OpenAI.Codex`, `PATH`, `Get-Volume`, `codex features list`, `templates/*`, `config.toml` cũ (đọc chỉ-đọc Luồng 1) | `~/.codex-official/config.toml`, `~/.codex*/rules/default.rules`, `~/.codex*/AGENTS.md`, `~/.codex-official/.rollback/latest.json`, 6 NTFS Junctions, 3 wrapper `.cmd` + 3 POSIX shim không đuôi trong `~/.local/bin/` |
| [`scripts/setup-dual-lane.sh`](../scripts/setup-dual-lane.sh) | Bash (`set -euo pipefail`, macOS / Linux / WSL) | Bộ cài đặt tương đương cho hệ Unix (hỗ trợ `--dry-run`, đường dẫn tương đối `--repo-path .`, kế thừa chỉ-đọc `[projects."..."]` từ `~/.codex/config.toml` + `--share-auth-to-lane2`, `--configure-cli-gateway` / `--cli-api-key-env`, `umask 077` / `chmod 700` / `chmod 600`, ghi nguyên tử `mktemp`, TOML merge giữ khóa top-level & section, wrapper worktree fail-closed cứng, nhật ký rollback tăng dần 5 cột SHA-256 + `original_mode` tại `.rollback/latest.tsv`, `--install-bridge`, `--sync-sessions`, `--use-git-worktree`) | `type -ap codex`, `codex features list`, `templates/*`, `config.toml` cũ (đọc chỉ-đọc Luồng 1) | `~/.codex-official/config.toml`, `~/.codex-official/.rollback/latest.tsv`, 6 symlinks (`ln -s`), `rules/default.rules`, `AGENTS.md`, 3 wrapper shell trong `~/.local/bin/` |
| [`scripts/restore-original.ps1`](../scripts/restore-original.ps1) | PowerShell 5.1+ / 7+ (Windows) | **Khôi phục chính xác 1 chạm** về trạng thái gốc dựa trên manifest `.rollback/latest.json` (kể cả manifest bán phần `Completed: false` sau cài đặt bị ngắt) với preflight kiểm chứng **SHA-256**, chuẩn hóa đường dẫn dài 8.3, khóa phạm vi đường dẫn phía caller & chặn reparse point, idempotent nhiều lần chạy (hỗ trợ `-DryRun`/`-WhatIf`, `-SnapshotPath`, `-RemoveLane2Home`) | `~/.codex-official/.rollback/latest.json`, các bản `.backup-*`, mã băm SHA-256 | Tháo an toàn 6 NTFS Junction bằng Win32 `Directory.Delete` trước, hoàn trả nguyên tử byte-exact từng tệp cấu hình cũ (giữ bản sao lưu nếu tệp đang bị khóa & giữ nguyên launcher cũ chưa chạm tới), gỡ 3 wrapper `.cmd` và chỉ cập nhật `PATH` khi thực sự có mục khớp |
| [`scripts/restore-original.sh`](../scripts/restore-original.sh) | Bash (`set -euo pipefail`, macOS / Linux / WSL) | Công cụ khôi phục chính xác tương đương cho macOS / Linux / WSL (hỗ trợ `--snapshot PATH`, `--dry-run`, `--remove-lane2-home`, preflight kiểm chứng manifest `.rollback/latest.tsv` kể cả `# status=in-progress` + SHA-256 + `original_mode` `000`–`777` & chặn symlink/path traversal/SUID, idempotent) | `~/.codex-official/.rollback/latest.tsv`, các bản `.backup-*` và symlink trong `~/.codex-official` | Tháo an toàn symlink trước, hoàn trả byte-exact từng tệp + đúng quyền POSIX qua staging `mktemp` nguyên tử và chỉ gỡ wrapper do bộ kit sinh (không xóa launcher cũ chưa chạm tới) |
| [`scripts/doctor.ps1`](../scripts/doctor.ps1) | PowerShell 5.1+ / 7+ (Windows) | Kiểm tra sức khỏe, tương thích hệ thống, thứ tự `PATH`, 6/6 đích Junction (chuẩn hóa đường dẫn dài 8.3), 7 probe `execpolicy`, quét plaintext secret, kiểm tra NTFS Allow-ACE `CodexSandboxUsers`, kiểm tra tham khảo chỉ-đọc `.sandbox\deny_read_acl_state.json` & kiểm tra chỉ-đọc **Rollback Journal** (**Chỉ đọc — Read-Only**) | `OSVersion`, `Get-Volume`, `Get-Command codex/codex-t3/python`, đích Junction, `default.rules`/`AGENTS.md`/`config.toml`, `Get-Acl`, `.sandbox\deny_read_acl_state.json` *(chỉ đọc trạng thái)*, `.rollback\latest.json` *(chỉ đọc trạng thái)*, `auth.json` *(chỉ đọc `auth_mode` đã lọc)* | **Không ghi bất kỳ tệp nào** |
| [`scripts/doctor.sh`](../scripts/doctor.sh) | Bash (`set -euo pipefail`, macOS / Linux / WSL) | Phiên bản chẩn đoán hệ thống, kiểm tra quyền POSIX `0600`, rò rỉ plaintext `api_key =`, 5 probe thực thi `execpolicy` & kiểm tra chỉ-đọc **Rollback Journal** (`# status=in-progress` / symlink) tương đương cho Unix (**Chỉ đọc — Read-Only**) | `uname`, `df`, `command -v codex/codex-t3/python3`, 6 symlinks, `default.rules`/`AGENTS.md`/`config.toml`, `.rollback/latest.tsv`, quyền POSIX (`stat`), trường `auth_mode` trong `auth.json` | **Không ghi bất kỳ tệp nào** |
| [`scripts/sync-sessions.py`](../scripts/sync-sessions.py) | Python 3.8+ (thư viện chuẩn `sqlite3`, `json`, `os`, `re`, `pathlib`, `tempfile`) | Đồng bộ tên phiên, mục đã ghim (`Pinned`) & `Goals` từ Luồng 1 (mở **chỉ-đọc `?mode=ro` + `PRAGMA query_only=ON`**) sang Luồng 2 bằng SQL tham số hóa + allowlist bảng/cột, chống symlink/path-traversal sidecar & ghi JSONL nguyên tử `0600` (hỗ trợ `--pinned-only`, `--dry-run`) | `~/.codex/session_index.jsonl`, `~/.codex/state_*.sqlite` *(read-only URI + `PRAGMA quick_check(1)`)*, `~/.codex/goals_*.sqlite` *(read-only URI)*, `PRAGMA table_info(...)` | `~/.codex-official/session_index.jsonl` *(temp `0600` + `fsync` + `os.replace`)*, `~/.codex-official/state_*.sqlite`, `~/.codex-official/goals_*.sqlite` *(kèm `PRAGMA wal_checkpoint(TRUNCATE)`)* |

### 2.2. Tệp mẫu chính sách & phối hợp (`templates/`)

| Tệp | Mục đích & Hành vi thực thi |
| :--- | :--- |
| [`templates/default.rules`](../templates/default.rules) | Bộ luật **Execpolicy (Starlark)** nạp vào tầng Rust của Codex (có chú thích chi tiết từng nhóm lệnh & cách tùy biến an toàn): chặn cứng (`forbidden`) nhóm lệnh phá hệ thống/ransomware (`vssadmin`, `bcdedit`, `wbadmin`, `diskpart`, `format`), cài persistence/Registry (`schtasks`, `sc`, `reg add/delete/import`), phá NTFS ACL/mạng (`icacls`, `takeown`, `net`, `net1`, `netsh`), xóa lịch sử Git (`git push --force/-f`), trình thông dịch corpus & Windows LOLBins để ép phân tích tĩnh (`php`, `ruby`, `perl`, `cscript`, `wscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `msiexec`, `wmic`, `Start-Process`/`start-process`/`saps`, `Invoke-Expression`/`invoke-expression`/`iex`/`IEX`), kèm biến thể `.exe`/`.com`; bắt buộc hỏi xác nhận (`prompt`) với `git push`, `git reset --hard`, `git clean`; và để trống 100% (`matchedRules: []`) cho toàn bộ lệnh duyệt cây thư mục & thao tác file CRUD (`rg`, `find`, `git status`, `Get-ChildItem`, `Remove-Item`, `rm`, `mv`, `cp`, `mkdir`, `apply_patch`). |
| [`templates/AGENTS.lane1.md`](../templates/AGENTS.lane1.md) | Chỉ thị toàn cục cài vào `~/.codex/AGENTS.md` cho **Luồng 1 (Codex Desktop — Tài khoản chính `acc chính`, giữ toàn quyền như trước)**: chống Prompt Injection, **cách ly chỉ phân tích tĩnh (`Static-Analysis-Only` — chỉ cấm thực thi mẫu/payload bên thứ 3)**, cấm đọc/in `config.toml`/`auth.json`/`.rollback/`/`.env`/`.ssh/`, giữ kỷ luật artifact, và khẳng định **Codex Desktop giữ toàn quyền (`toàn quyền như trước`) nắm toàn bộ cây thư mục, đọc/ghi/tạo/sửa/xóa file, build & test trên toàn dự án mặc định (Rule 4 & Rule 6, chỉ chia phân vùng nếu người dùng chủ động khai báo nhiệm vụ song song trong `DUAL_LANE_BRIDGE.md`)**. |
| [`templates/AGENTS.lane2.md`](../templates/AGENTS.lane2.md) | Chỉ thị toàn cục cài vào `~/.codex-official/AGENTS.md` cho **Luồng 2 (Codex CLI — Linh hoạt Login OAuth & API Key / Gateway)**: cùng chuẩn bảo vệ, cách ly phân tích tĩnh & toàn quyền nắm cây thư mục + File CRUD trong workspace (Rule 6) với Luồng 1, bổ sung luật **Zero-Collision** (không sửa vùng tệp/catalog của Luồng 1, dùng `CARGO_TARGET_DIR` riêng, đọc chéo handoff của Luồng 1). |
| [`templates/DUAL_LANE_BRIDGE.md`](../templates/DUAL_LANE_BRIDGE.md) | Tệp cầu nối mẫu để chép vào dự án của bạn (`artifacts/dual-lane/DUAL_LANE_BRIDGE.md`), phân định rõ vai trò Luồng 1 (Desktop `acc chính`) vs. Luồng 2 (CLI Login & API Key), toàn quyền nắm cây thư mục & File CRUD trong vùng sở hữu, quy tắc an toàn bắt buộc giữ nguyên, và lưu ý ranh giới mềm vs. cứng (`-UseGitWorktree` / `--use-git-worktree`). |

### 2.3. Tài liệu & cấu hình repo (`docs/`, gốc repo)

| Tệp | Nội dung |
| :--- | :--- |
| [`README.md`](../README.md) | Trang tổng quan, bảng chọn kịch bản theo nhu cầu, ranh giới bảo mật minh bạch, sơ đồ kiến trúc và lệnh cài nhanh 3 bước. |
| [`docs/GUIDE_AND_MANIFEST.md`](./GUIDE_AND_MANIFEST.md) | Chính tài liệu bạn đang đọc — khai báo chi tiết mã nguồn, hàm, bảng tham số đầy đủ và hướng dẫn gỡ bỏ an toàn. |
| [`docs/REAL_CODEX_CHECKLIST.md`](./REAL_CODEX_CHECKLIST.md) | Danh sách lệnh kiểm chứng thực nghiệm trước & sau khi cài đặt (0 plaintext key, behavioral `execpolicy check`, kiểm tra ACL/chmod, merge TOML, UPSERT SQLite và rollback `-DryRun`). |
| [`docs/SECURITY_MODEL.md`](./SECURITY_MODEL.md) | Phân tích sâu 4 lớp phòng thủ, bảng minh bạch Bộ Kit vs. Giới hạn OS/Codex runtime (bao gồm kế thừa `CodexSandboxUsers`, atomic replace reset DACL, `keyring` + `env_key`), ranh giới Mềm vs. Cứng và Khiên Git. |
| [`docs/TROUBLESHOOTING.md`](./TROUBLESHOOTING.md) | Hướng dẫn khắc phục 10 lỗi thực chiến thường gặp (bao gồm cảnh báo Defender trên `.jsonl`, reset `kernel_acl` sau `codex features`, phục hồi cài đặt bị ngắt giữa chừng và lỗi từ chối chạy khi worktree bị xóa). |
| [`tests/test_sync_sessions.py`](../tests/test_sync_sessions.py) | Bộ Unit Test Python (`unittest`) kiểm chứng đọc nguồn `?mode=ro`, UPSERT (`INSERT` + `UPDATE`), atomic JSONL, `--pinned-only`, lệch schema, path-traversal/symlink và `--dry-run`. |
| [`tests/test-kit.ps1`](../tests/test-kit.ps1) | Bộ Test PowerShell 12 pha kiểm chứng AST, `-DryRun`/`-WhatIf`, merge `config.toml` không phá hủy, cô lập `env_key` & `-GatewayTargetLane` / `-ConfigureCliGateway` (Luồng 2 CLI vừa hỗ trợ Login vừa hỗ trợ API Key), kế thừa chỉ-đọc `[projects."..."]` từ Desktop mà giữ SHA-256 của `~/.codex/config.toml` nguyên vẹn 100%, đường dẫn tương đối `-RepoPath .`, POSIX shim không đuôi cho Git Bash/MSYS2, UTF-8 không BOM, khóa ACL 2 bước & `-ReapplyAclOnly`, chuẩn hóa đường dẫn ngắn 8.3 (`RUNNER~1`), worktree fail-closed cứng, `doctor.ps1`, chống path-traversal, khôi phục SHA-256, khôi phục cài đặt bị ngắt giữa chừng, vòng lặp 3x install/rollback, bảo toàn link có trước (`SharedLinkRecords`), khôi phục đúng thư mục backup và preflight fail-closed khi thiếu backup. |
| [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | Pipeline GitHub Actions CI 4 job (`hygiene-and-policy`, Windows PS 5.1 & 7+, Ubuntu, macOS) tự động chạy kiểm tra cú pháp, unit test, smoke test fail-closed worktree, line-ending/BOM, quét rò rỉ bí mật, khôi phục cài đặt bị ngắt và vòng lặp 3x install/rollback. |
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
9. **Kế thừa Chỉ-đọc `[projects.*]` từ Desktop & Hợp nhất không phá hủy `~/.codex-official/config.toml` (Luồng 2 Codex CLI):** Đọc **chỉ-đọc (`read-only`)** `~/.codex/config.toml` (nếu có) để tự động kế thừa toàn bộ danh sách `[projects."..."]` đã `trusted` trên Codex Desktop sang `~/.codex-official/config.toml` (không chạm 1 byte nào vào `~/.codex/config.toml`, chuẩn hóa đường dẫn dài 8.3 chống trùng lặp), giữ nguyên các section tùy biến (`[mcp_servers.*]`, `[tui]`, `[plugins.*]`), escape chuỗi TOML, đặt `sandbox_mode = "workspace-write"`, `approval_policy = "$ApprovalPolicy"`, `network_access = false` (trừ khi bật `-AllowSandboxNetwork`), `daemon_auto_start = false` (khi hỗ trợ), lọc biến môi trường nhạy cảm, tách `CARGO_TARGET_DIR`, khóa ACL và ghi checkpoint. Nếu bật `-ShareAuthToLane2` (alias `-ShareOfficialAuth`), sao chép nguyên tử `~/.codex/auth.json` sang `~/.codex-official/auth.json` kèm sao lưu rollback và khóa ACL 2 bước (giữ `~/.codex/auth.json` nguyên vẹn 100%).
10. ***(Tùy chọn `-ConfigureCliGateway` hoặc `-ConfigureGateway` + `-GatewayTargetLane Lane1|Lane2|Both`)* Cấu hình API Key / cổng Gateway linh hoạt (giữ Codex Desktop toàn quyền như trước):** Mặc định (và khi truyền `-ConfigureCliGateway` hoặc `-GatewayTargetLane Lane2`), tệp `~/.codex/config.toml` của **Codex Desktop (Luồng 1 — Tài khoản chính `acc chính`) không bị chỉnh sửa 1 byte nào**, giữ nguyên 100% quyền hạn, cấu hình và mạng gốc của Desktop; ngay cả khi truyền `-GatewayTargetLane Lane1` hoặc `Both`, bộ kit chỉ merge không phá hủy cấu hình provider (`env_key`) và **không bao giờ ép `sandbox_mode` hạn chế hay `network_access = false` vào `~/.codex/config.toml`**. Trên Luồng 2 (`~/.codex-official`, Codex CLI), `-ConfigureCliGateway` (hoặc `-GatewayTargetLane Lane2` / `Both`) cho phép CLI dùng song song hoặc linh hoạt cả **API Key / Gateway (`env_key` qua `-CliApiKeyEnv` / `-GatewayApiKeyEnv`) lẫn Đăng nhập OAuth (`codex login` / `-ShareAuthToLane2`)**. Khuyến nghị nhập key ẩn qua `-PromptGatewayApiKey` hoặc đặt trước biến môi trường `-CliApiKeyEnv` (**không bao giờ ghi plaintext key** vào `config.toml` hay `.backup-*`). Lưu bản sạch `~/.codex/config.backup.toml` khi sửa Luồng 1 (đồng thời theo dõi `ExistedPrior = false` trong manifest để rollback không để lại tệp rác).
11. **Sao lưu launcher cũ (nếu có) & tạo bộ launcher đa Shell (`.cmd` + POSIX shim không đuôi) trong `~/.local/bin/`:** Từng launcher (`codex.cmd`, `codex-official.cmd`, `codex-t3.cmd` cùng 3 POSIX shim không đuôi chuẩn LF `codex`, `codex-official`, `codex-t3` cho Git Bash / MSYS2) được sao lưu, ghi và checkpoint riêng lẻ (nếu cài đặt bị ngắt giữa Bước 11, các launcher chưa chạm tới vẫn còn nguyên). Sinh wrapper mới (escape `%` bằng `Escape-CmdSetValue`, tự thêm `chcp 65001 >nul` khi đường dẫn có Unicode, tự dò lại gói `WindowsApps`). Khi bật `-UseGitWorktree`, wrapper Luồng 2 áp dụng **Hard Fail-Closed Worktree Isolation**: so khớp cả đường dẫn dài chuẩn lẫn tên ngắn 8.3 (`%%~fs`), tự chuyển `cwd` từ repo gốc lẫn **mọi thư mục con** sang worktree Luồng 2, hậu kiểm `cwd` sau `cd`, **từ chối chạy (`exit 1`)** nếu worktree thiếu/bị xóa/lỗi `cd` (tắt auto-cd chỉ bằng `CODEX_NO_AUTO_WORKTREE_CD=1`), và Guard 2 luôn chặn `-C`/`-C=`/`-C<path>`/`-C"<path>"`/`--cd`/`--cd=`/`--add-dir`/`--add-dir=` trỏ về repo chính. Đồng thời đưa `~/.local/bin` lên đầu User `PATH` (trừ khi truyền `-SkipPathUpdate`). *(Cờ `-ReapplyAclOnly` cho phép khóa nhanh lại ACL trong ~1 giây sau khi Codex cập nhật cấu hình.)*
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
| `Get-ExistingTrustedProjects` | `ConfigPaths[]` | Quét các `config.toml` cũ của cả Luồng 1 & Luồng 2 (đọc tường minh `-Encoding UTF8`) để giữ nguyên 100% danh sách `[projects.'...']` / `[projects."..."]` đã đánh dấu `trusted`. |
| `Merge-CodexConfigToml` | `ExistingPath`, `ManagedTopBlock`, `ManagedSectionsBlock`, `ManagedTopKeys[]`, `ManagedSectionNames[]` | Hợp nhất không phá hủy vào `config.toml` hiện có: giữ nguyên mọi khóa top-level (kể cả mảng/bảng nhiều dòng), comment `#` sau header section, `[[array_of_tables]]` và section tùy chỉnh (`[mcp_servers.*]`, `[tui]`, `[plugins.*]`), loại bỏ `experimental_bearer_token` cũ và chỉ cập nhật phần do Dual-Lane quản lý. |

#### `scripts/doctor.ps1` (PowerShell 5.1+ / 7+ — Chỉ đọc)
| Thành phần / Mục kiểm tra | Thực hiện chính xác điều gì |
| :--- | :--- |
| `Report` | Định dạng và thống kê 3 trạng thái `[PASS]` / `[WARN]` / `[FAIL]`; thoát mã `1` nếu có `[FAIL]` (vd ổ không phải NTFS, phát hiện plaintext secret trong `config.toml`, hoặc lệnh bắt buộc cấm lại bị `execpolicy` cho phép), mã `0` nếu không có `[FAIL]`. |
| 9 nhóm kiểm tra thật (Read-Only) | (1) OS & PowerShell; (2) Toàn bộ ổ đĩa cố định, NTFS & dung lượng trống thật; (3) Thứ tự `PATH` & phiên bản `codex` / `codex-t3`; (4) Tình trạng & đích trỏ thật của 6/6 NTFS Directory Junction (chuẩn hóa đường dẫn dài 8.3); (5) Đầy đủ `config.toml` + `default.rules` + `AGENTS.md`, trạng thái `Static-Analysis-Only`, `sandbox_net=restricted/enabled`, `[shell_environment_policy]` & **7 live probe `codex execpolicy check`** (`php`, `mshta`, `vssadmin`, `icacls`, `git push --force`, `Start-Process`, `iex`); (6) Quét `config.toml` trong bộ nhớ chống plaintext `experimental_bearer_token` / `api_key` *(tuyệt đối không in giá trị secret)*; (7) Cách ly `auth.json` *(chỉ đọc `auth_mode` đã lọc theo allowlist)*, kiểm tra **Allow ACE** của `CodexSandboxUsers` + `AreAccessRulesProtected`, và kiểm tra tham khảo chỉ-đọc `.sandbox\deny_read_acl_state.json`; (8) Trạng thái **Rollback Journal** (`.rollback\latest.json` — báo `[WARN]` nếu `Completed=false` do cài đặt bị ngắt giữa chừng hoặc bị thay bằng reparse point); (9) Tình trạng Python 3 thật cho `sync-sessions.py`. |

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
* `setup-dual-lane.sh`: Chạy với `set -euo pipefail`, `umask 077`, `chmod 700` trên thư mục Codex/`.rollback` và `chmod 600` trên `config.toml`/`auth.json`/bản sao lưu nội bộ, ghi tệp nguyên tử qua `mktemp` + `trap` dọn tệp tạm (hỗ trợ `INT`/`TERM`), từ chối ghi đè symlink, merge không phá hủy cả top-level key lẫn `[section]` của `config.toml`, sinh 3 wrapper với `shell_quote()` (khi bật `--use-git-worktree`, áp dụng **Hard Fail-Closed Worktree Isolation**: tự chuyển `cwd` từ repo gốc lẫn thư mục con sang worktree Luồng 2, hậu kiểm `pwd -P`, **từ chối chạy `exit 1`** nếu worktree thiếu/bị xóa/symlink/lỗi `cd`, và Guard 2 luôn chặn `-C`/`-C=`/`-C<path>`/`--cd`/`--cd=`/`--add-dir`/`--add-dir=` trỏ vào repo chính), và ghi tăng dần (`flush_rollback_manifest`) manifest 5 cột SHA-256 + `original_mode` (`# status=in-progress` $\rightarrow$ `# status=complete`) tại `~/.codex-official/.rollback/latest.tsv`.
* `doctor.sh`: Chạy chỉ-đọc (`set -euo pipefail`, `umask 077`), kiểm tra 6 symlink không gãy/lệch đích, kiểm tra `[sandbox_workspace_write] network_access = false`, cảnh báo nếu phát hiện plaintext `api_key =` (không in giá trị), chạy **5 live probe `codex execpolicy check`** (`php`, `mshta`, `vssadmin`, `Start-Process`, `iex`), kiểm tra quyền POSIX `0600` (zero-pad octal), kiểm tra chỉ-đọc **Rollback Journal** (`# status=in-progress` hoặc symlink `.rollback`), và chỉ in `auth_mode` đã lọc theo allowlist.
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
| `-LocalBin` | `string` | `%USERPROFILE%\.local\bin` | Thư mục lưu `codex.cmd`, `codex-official.cmd`, `codex-t3.cmd` cùng 3 POSIX shim không đuôi (`codex`, `codex-official`, `codex-t3`) cho Git Bash / MSYS2 |
| `-CargoTargetDir` | `string` | `%TEMP%\codex-lane2-target` | Thư mục build Cargo riêng cho Luồng 2 (đổi sang ổ khác nếu ổ `C:` ít dung lượng) |
| `-OfficialModel` | `string` | *(để trống)* | Đặt model mặc định cố định cho Luồng 2 (vd `<model-slug>` được tài khoản hỗ trợ) |
| `-OfficialReasoning` | `string` | *(để trống)* | Đặt mức suy luận (`low`, `medium`, `high`, `ultra`) nếu muốn cố định |
| `-OfficialServiceTier` | `string` | *(để trống)* | Đặt `service_tier` nếu tài khoản của bạn hỗ trợ |
| `-ApprovalPolicy` | `on-request` \| `never` | `on-request` | Mặc định an toàn (`on-request`); chỉ truyền `never` khi chạy tự động đã cô lập |
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
| `-ShareAuthToLane2` *(alias: `-ShareOfficialAuth`)* | `switch` | `false` | Sao chép nguyên tử `~/.codex/auth.json` (nếu có) sang `~/.codex-official/auth.json` kèm sao lưu rollback và khóa ACL 2 bước (giữ `~/.codex/auth.json` nguyên vẹn 100%) |
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
| `--repo PATH` *(hoặc `--repo-path PATH` / đối số vị trí `REPO_PATH`)* | Thư mục hiện tại | Đường dẫn dự án muốn đánh dấu `trusted` (hỗ trợ cả đường dẫn tương đối như `.` hoặc `./sub`) |
| `--approval-policy MODE` *(hoặc `CODEX_APPROVAL_POLICY`)* | `on-request` | `on-request` (mặc định an toàn) hoặc `never` |
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
| `--share-auth-to-lane2` *(alias: `--share-official-auth`)* | tắt | Sao chép nguyên tử `~/.codex/auth.json` (nếu có) sang `~/.codex-official/auth.json` với `chmod 600` và theo dõi rollback (giữ `~/.codex/auth.json` nguyên vẹn 100%) |
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

## 5. Cơ chế Khôi phục Chính xác 1 Chạm (Deterministic SHA-256 Rollback — v1.3.1)

Mỗi khi chạy `setup-dual-lane.ps1` (Windows) hoặc `setup-dual-lane.sh` (macOS / Linux / WSL), bộ cài khởi tạo **nhật ký rollback tăng dần chống crash (Crash-Safe Incremental Rollback Journal)** tại `~/.codex-official/.rollback/latest.json` (Windows, `Completed: false -> true`) hoặc `~/.codex-official/.rollback/latest.tsv` (Unix, `# status=in-progress -> complete`), kèm bản lịch sử `snapshot-yyyyMMdd-HHmmss[-N].*`, và cập nhật nguyên tử **ngay sau từng thao tác** (tạo Junction/symlink, tính SHA-256 & sao lưu tệp cấu hình gốc, cài từng launcher).

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
