# Danh sách Kiểm chứng Thực tế (Real Codex Verification Checklist)

> **Tác giả:** Lê Hoàng Ngọc Tươi | **Dự án:** Codex Dual-Lane & Security Kit (Apache License 2.0)  
> Danh sách này giúp bạn (hoặc đội kiểm duyệt an ninh) tự kiểm chứng bằng lệnh thực tế từng cơ chế bảo vệ, ACL, `execpolicy`, TOML merge, SQLite UPSERT và khôi phục SHA-256 trước và sau khi cài đặt — không tin mù quáng vào cấu hình tĩnh.
>
> **Ranh giới minh bạch CI vs. Codex Runtime thật:** **4/4 job xanh trên GitHub Actions CI** (`hygiene-and-policy`, Windows PS 5.1 & 7+, Ubuntu, macOS) kiểm chứng logic script, bảo toàn `trust_level`, worktree fail-closed và rollback **bằng các binary `codex` giả lập (`mock codex`)** trên đa hệ điều hành. CI xanh 4/4 **không thay thế** cho việc chạy `scripts/doctor.ps1` / `scripts/doctor.sh` và tự kiểm chứng các mục dưới đây trực tiếp trên **đúng phiên bản Codex Desktop/CLI thật đang cài trên máy bạn** (và chạy lại sau mỗi lần nâng cấp Codex).

---

## 1. Kiểm chứng Không lưu Plaintext API Key trong `config.toml` & Bản sao lưu (Linh hoạt Luồng 2 CLI & Luồng 1 Desktop)

Khi dùng `-ConfigureCliGateway` / `-ConfigureGateway` (kèm `-GatewayTargetLane Lane2|Lane1|Both` trên Windows hoặc `--configure-cli-gateway` / `--configure-gateway --gateway-target-lane lane2|lane1|both` trên Unix), bộ kit dùng thuộc tính `env_key = "<TEN_BIEN_MOI_TRUONG>"` của Codex (đọc từ biến môi trường User) thay vì ghi trực tiếp key vào `config.toml` — đồng thời mặc định giữ nguyên 100% `~/.codex/config.toml` để **Codex Desktop (`~/.codex`, Luồng 1 — `acc chính`) được toàn quyền như trước**:

**Windows (PowerShell):**
```powershell
# Kiểm tra hoàn toàn không có chuỗi "sk-" hay "experimental_bearer_token" trong config.toml và các bản backup (.backup-*):
Select-String -Path "$env:USERPROFILE\.codex\config*.toml*","$env:USERPROFILE\.codex-official\config*.toml*" `
    -Pattern "experimental_bearer_token|sk-[A-Za-z0-9]{10,}"
```
**macOS / Linux / WSL (Bash):**
```bash
grep -En 'experimental_bearer_token|sk-[A-Za-z0-9]{10,}' \
    ~/.codex/config*.toml* ~/.codex-official/config*.toml* 2>/dev/null || true
```
* **Kỳ vọng:** Không có kết quả nào (`0` dòng khớp).
* **Cảnh báo opt-in `-ShareAuthToLane2` / `--share-auth-to-lane2` (tắt mặc định):** Cờ này chỉ chạy khi bạn chủ động truyền vào; khi bật nó sẽ **tạo bản sao thứ 2 của `auth.json` (OAuth token)** tại Luồng 2 (`~/.codex-official/auth.json`) và phát cảnh báo `[WARN]` (cảnh báo mức cao hơn nếu đi cùng cờ gateway bên thứ 3). **Nên tránh hoặc hết sức thận trọng khi Luồng 2 đang cấu hình cổng API bên thứ 3.**
* **Khuyến nghị nâng cao:** Nếu phiên bản Codex của bạn hỗ trợ, cấu hình thêm `cli_auth_credentials_store = "keyring"` để chuyển token đăng nhập từ tệp `auth.json` vào OS Credential Store / Keyring.

---

## 2. Kiểm chứng Thực thi Engine `execpolicy` (Behavioral Check — Không chỉ đọc chuỗi)

Thay vì chỉ kiểm tra tệp `default.rules` có tồn tại hay không, hãy gọi trực tiếp bộ máy **Starlark Execpolicy (Rust)** của Codex để xác nhận quyết định thực tế cho các nhóm lệnh chặn cứng (`forbidden`), biến thể `.exe`/chữ thường và nhóm yêu cầu duyệt (`prompt`):

```powershell
$rules = "$env:USERPROFILE\.codex-official\rules\default.rules"

# Nhóm phải trả về "decision":"forbidden":
codex execpolicy check --rules $rules -- php -r "echo 1;"
codex execpolicy check --rules $rules -- mshta http://example.invalid
codex execpolicy check --rules $rules -- vssadmin delete shadows /all
codex execpolicy check --rules $rules -- vssadmin.exe delete shadows /all
codex execpolicy check --rules $rules -- icacls.exe "$env:USERPROFILE\.codex\auth.json"
codex execpolicy check --rules $rules -- Start-Process calc.exe
codex execpolicy check --rules $rules -- start-process calc.exe
codex execpolicy check --rules $rules -- iex "dir"
codex execpolicy check --rules $rules -- git push --force

# Nhóm phải trả về "decision":"prompt":
codex execpolicy check --rules $rules -- git push
codex execpolicy check --rules $rules -- git reset --hard

# Nhóm lệnh duyệt cây thư mục & thao tác file CRUD trong workspace phải trả về matchedRules rỗng ([] — được phép 100%):
codex execpolicy check --rules $rules -- git status
codex execpolicy check --rules $rules -- rg --files
codex execpolicy check --rules $rules -- Get-ChildItem -Recurse
codex execpolicy check --rules $rules -- Remove-Item .\scratch.tmp
```
* **Kỳ vọng:** 9 lệnh đầu trả về `"decision":"forbidden"`, 2 lệnh `git push` / `git reset --hard` trả về `"decision":"prompt"`, và toàn bộ nhóm lệnh duyệt cây thư mục & thao tác file CRUD (`git status`, `rg --files`, `Get-ChildItem`, `Remove-Item`, `rm`, `mv`, `cp`, `mkdir`) trả về `{"matchedRules":[]}` (hoàn toàn không bị cản trở trong workspace).
* **Giới hạn kỹ thuật cần nhớ:** `prefix_rule` kiểm khớp chính xác theo tiền tố lệnh trực tiếp (`argv[0]`), không phân tích hết chuỗi lồng trong `powershell -Command "..."` hay `bash -c "..."`. Các chuỗi lồng nhau được kiểm soát bởi **Lớp 1 OS Sandbox (`workspace-write` + `network_access = false`)**, **`approval_policy = "on-request"`** và **Lớp 4 `AGENTS.md`**.

---

## 3. Kiểm chứng Ngắt mạng Shell Sandbox & Nạp `AGENTS.md`

```powershell
codex debug prompt-input | Select-String -Pattern "Network access is restricted|Static-Analysis-Only"
```
* **Kỳ vọng:** Xuất hiện đồng thời cả hai dòng:
  * `Network access is restricted.`
  * `2. **Static-Analysis-Only Isolation (NEVER Execute Analyzed Samples/Binaries)**`

---

## 4. Kiểm chứng Quyền Tệp NTFS ACL (Windows) / POSIX `0600` (Unix)

**Windows (PowerShell):**
```powershell
# Kiểm tra toàn diện read-only (bao gồm live execpolicy probes & kernel_acl):
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\doctor.ps1

# Hoặc kiểm tra trực tiếp Allow ACE của CodexSandboxUsers trên từng tệp nhạy cảm:
foreach ($f in @("$env:USERPROFILE\.codex\auth.json","$env:USERPROFILE\.codex\config.toml","$env:USERPROFILE\.codex-official\auth.json","$env:USERPROFILE\.codex-official\config.toml")) {
    if (Test-Path -LiteralPath $f) {
        $leaks = @((Get-Acl -LiteralPath $f).Access | Where-Object {
            $_.IdentityReference -like '*CodexSandboxUsers*' -and $_.AccessControlType -eq 'Allow'
        })
        Write-Host ("{0} => CodexSandboxUsers Allow ACEs: {1}" -f $f, $leaks.Count)
    }
}
```
* **Kỳ vọng:** `CodexSandboxUsers Allow ACEs: 0` (và `doctor.ps1` báo `kernel_acl=locked`, đồng thời không báo nhầm trên Deny ACE bảo vệ nếu có).
* **Lưu ý thực tế:** Khi `codex` CLI/Desktop chạy `codex features ...`, sửa Settings trên App, hoặc tạo mới `auth.json` bằng ghi đè atomic, Windows sẽ áp lại quyền kế thừa `CodexSandboxUsers:(OI)(CI)(RX)` từ thư mục cha (script bên ngoài không thể ngăn trước thao tác ghi của chính Codex). Hãy chạy `.\scripts\doctor.ps1` và nếu thấy `kernel_acl=EXPOSED`, chạy ngay `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 -ReapplyAclOnly` (và giữ `env_key` + `cli_auth_credentials_store = "keyring"`).
* **Ranh giới CI (4/4 xanh bằng Mock `codex`) vs. Codex Runtime thật:** Bộ test trong `tests/test-kit.ps1` và **4/4 job xanh trên GitHub Actions CI** (Windows PS 5.1 & 7+, Ubuntu, macOS) kiểm chứng logic script, bảo toàn `trust_level` và rollback bằng các binary `codex` giả lập (`mock codex`) — **không thay thế** cho việc chạy `scripts/doctor.ps1` / `scripts/doctor.sh` và tự kiểm chứng Mục 1–4 trực tiếp trên đúng phiên bản **Codex Desktop/CLI thật** đang cài trên máy bạn.

**macOS / Linux / WSL (Bash):**
```bash
./scripts/doctor.sh
ls -la ~/.codex/config.toml ~/.codex/auth.json ~/.codex-official/config.toml ~/.codex-official/auth.json 2>/dev/null || true
```
* **Kỳ vọng:** Các tệp cấu hình và xác thực có quyền chỉ chủ sở hữu đọc/ghi (`-rw-------` / `0600`).

---

## 5. Kiểm chứng Merge `config.toml`, Bảo toàn Nghiêm ngặt `trust_level`, Cảnh báo Auth-Share, `-ConfigureCliGateway` / `-GatewayTargetLane`, Git Bash Shims, Đường dẫn 8.3, Worktree Fail-Closed, Quyền Sở hữu Link & Preflight Fail-Closed (v1.3.3)

Chạy bộ test tích hợp 12 pha trên Windows (không đụng tới `~/.codex*` thật của bạn, dùng thư mục tạm cô lập; tương đương trên Unix là Section 9a–9e trong `.github/workflows/ci.yml`):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\test-kit.ps1
```
* **Kỳ vọng:** Toàn bộ 12 pha kiểm tra đều báo `[PASS]`: cú pháp AST & CRLF, unit test Python, Starlark `default.rules`, `-DryRun`/`-WhatIf`, TOML merge giữ nguyên `[mcp_servers.*]`/`[tui]`/`[projects.*]`, cô lập `env_key` & `-ConfigureCliGateway` / `-GatewayTargetLane` (giữ `~/.codex/config.toml` của Desktop nguyên vẹn 100% SHA-256 khi cấu hình `Lane2`, kế thừa chỉ-đọc `[projects."..."]` từ Desktop sang CLI với **bảo toàn nghiêm ngặt `trust_level`** — `trusted` giữ `"trusted"`, `untrusted` ở cả Luồng 1 lẫn Luồng 2 giữ nguyên `"untrusted"` và tuyệt đối không bị nâng cấp, mục thiếu `trust_level` không bao giờ bị nâng cấp lên `"trusted"` — phát cảnh báo `[WARN]` cho cờ opt-in `-ShareAuthToLane2` đặc biệt khi đi kèm `-ConfigureCliGateway`, hỗ trợ đường dẫn tương đối `-RepoPath .` và POSIX shim không đuôi cho Git Bash/MSYS2), UTF-8 không BOM, khóa ACL 2 bước & `-ReapplyAclOnly`, chuẩn hóa đường dẫn ngắn 8.3 (`RUNNER~1`/`PROGRA~1` qua `GetLongPathNameW` + `%%~fs`), worktree fail-closed cứng (từ chối chạy khi worktree bị xóa/thay bằng tệp thường/lỗi `cd`, chỉ tắt auto-cd với `CODEX_NO_AUTO_WORKTREE_CD=1` trong khi vẫn chặn `-C`/`-C<path>`/`--cd`/`--add-dir`), `doctor.ps1`, chống path-traversal, khôi phục SHA-256, phục hồi cài đặt bị ngắt giữa chừng (`.rollback/latest.json` `Completed=false`), vòng lặp cài đặt + khôi phục 3 lần liên tiếp (0 tệp backup rác, 0 mất dữ liệu Luồng 1), bảo toàn Junction/symlink có từ trước của người dùng (`SharedLinkRecords`), khôi phục thư mục từ đúng đường dẫn backup trong manifest (chống decoy backup), và kiểm tra preflight fail-closed khi thiếu backup (0 thay đổi trên đĩa).

---

## 6. Kiểm chứng Đồng bộ Phiên UPSERT (`INSERT` + `UPDATE`) & Bảo toàn Dữ liệu Nguồn

Chạy bộ unit test Python (không sửa bất kỳ DB Codex thật nào):

```powershell
python -m unittest discover -s .\tests -v
```
* **Kỳ vọng:** Tất cả unit test đều trả về `OK` (`0` failures, `0` errors), xác nhận đọc nguồn chỉ-đọc (`?mode=ro`), UPSERT vào DB đích trống, `--pinned-only`, ghi nguyên tử JSONL và `--dry-run` không sửa đĩa.

---

## 7. Kiểm chứng Xem trước Khôi phục An toàn (`DryRun`) & Chọn Ranh giới Mềm vs. Cứng

### 7.1. Kiểm tra tính toàn vẹn Snapshot trước khi cần rollback
```powershell
# Windows (chỉ đọc, kiểm tra SHA-256 của toàn bộ bản sao lưu trong .rollback/latest.json):
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1 -DryRun
```
```bash
# macOS / Linux / WSL (chỉ đọc):
./scripts/restore-original.sh --dry-run
```

### 7.2. Chọn đúng Ranh giới Phân vùng: Mềm (`AGENTS.md`) vs. Cứng (`-UseGitWorktree`)

| Chế độ | Cách kích hoạt | Bản chất kỹ thuật | Khi nào nên dùng |
| :--- | :--- | :--- | :--- |
| **Chế độ A: Chung 1 Worktree** *(Mặc định)* | Chạy `setup-dual-lane.ps1 -RepoPath "C:\Projects\my-app"` | **Ranh giới mềm (Soft Prompt Boundary):** Hai luồng phân chia thư mục qua `AGENTS.md` và `DUAL_LANE_BRIDGE.md`, nhưng cùng chia sẻ quyền ghi OS trong thư mục làm việc. | Khi muốn 2 luồng thấy ngay tệp mới của nhau trên cùng 1 cây thư mục mà không cần merge nhánh. |
| **Chế độ B: Tách Git Worktree riêng** *(Cưỡng chế cấp OS — Hard Fail-Closed)* | Thêm cờ **`-UseGitWorktree`** (Windows) hoặc **`--use-git-worktree`** (macOS/Linux/WSL) | **Ranh giới cứng fail-closed (Hard OS Sandbox Boundary):** Tạo worktree riêng `<repo>-lane2` trên nhánh `dual-lane-2`. Wrapper Luồng 2 tự chuyển `cwd` sang worktree (kể cả thư mục con & chuẩn hóa đường dẫn 8.3 ngắn), **từ chối chạy (`exit 1`)** nếu worktree bị xóa/thiếu/lỗi `cd` (không fallback về repo chính), và luôn chặn `-C`/`-C=`/`-C<path>`/`-C"<path>"`/`--cd`/`--add-dir` trỏ vào repo chính (ngay cả khi đặt `CODEX_NO_AUTO_WORKTREE_CD=1`). Ở tầng OS, `sandbox_mode = "workspace-write"` chặn ghi vật lý vào cây thư mục của Luồng 1. | Khi cần cưỡng chế phân quyền ghi tuyệt đối ở cấp hệ điều hành giữa 2 agent. |

---

## 8. Bằng chứng Kiểm chứng Thực tế trên Codex CLI Thật (`codex-cli 0.171.0-alpha.13` — Windows)

Toàn bộ kết quả dưới đây được đo trực tiếp trên binary **OpenAI Codex CLI thật (`codex-cli 0.171.0-alpha.13`)** trong thư mục tạm cô lập hoàn toàn (không đụng tới `~/.codex*`, `~/.local/bin` hay User `PATH` thật, sử dụng token canary giả lập):

### 8.1. Cài đặt thật, Wrapper, Worktree Fail-Closed & 13/13 Starlark `execpolicy` Probes
* **Cài đặt & Wrapper:** `setup-dual-lane.ps1` với `-UseGitWorktree -ConfigureGateway -GatewayApiKeyEnv CANARY_GW_ENV_PROBE -SkipPathUpdate` và binary `codex.exe` thật $\rightarrow$ `EXIT=0`. *(Lưu ý thực tế: khi đặt `CODEX_HOME` trong `%TEMP%`, `codex.exe` in cảnh báo không gây lỗi `Refusing to create helper binaries under temporary dir`).*
  * `codex.cmd --version` và `codex-t3.cmd --version` $\rightarrow$ `EXIT=0` (`codex-cli 0.171.0-alpha.13` đúng theo từng `CODEX_HOME`).
  * `codex.cmd features list` $\rightarrow$ `EXIT=0` (liệt kê `224` feature flags thật).
  * `codex.cmd debug prompt-input` $\rightarrow$ `EXIT=0`, xác nhận đồng thời cả `Network access is restricted` và `Static-Analysis-Only` đang hiệu lực ở Luồng 2.
* **Starlark `execpolicy check` sống (`13/13` PASS, `EXIT=0`):**
  * **9 lệnh `forbidden`:** `php -r "echo 1;"`, `mshta http://example.invalid`, `vssadmin delete shadows /all`, `vssadmin.exe delete shadows /all`, `icacls.exe <lane1>\auth.json`, `Start-Process calc.exe`, `start-process calc.exe`, `iex dir`, `git push --force` *(khớp cả `forbidden` & `prompt`, quyết định hiệu lực=`forbidden`)*.
  * **3 lệnh `prompt`:** `git push`, `git reset --hard`, `git clean -fd`.
  * **1 lệnh cho phép (`{"matchedRules":[]}`):** `git status`.
* **Worktree Fail-Closed trên `codex.cmd` thật:**
  * Chạy từ `<primaryRepo>` tự chuyển vào worktree (`EXIT=0`).
  * Guard 2 chặn **5/5 dạng cờ** trỏ vào `<primaryRepo>`: `-C <primaryRepo>`, `-C"<primaryRepo>"`, `-C<primaryRepo>`, `--cd=<primaryRepo>\src`, `--add-dir <primaryRepo>` $\rightarrow$ tất cả `EXIT=1` (`codex.exe` không chạy).
  * Sau khi xóa worktree (`git worktree remove --force`): `codex.cmd --version` từ `<primaryRepo>` $\rightarrow$ **`EXIT=1`** (`Refusing to fall back to primary repo`, `codex.exe` không chạy).
  * Khi đặt `CODEX_NO_AUTO_WORKTREE_CD=1` với worktree đã xóa: `codex.cmd --version` $\rightarrow$ `EXIT=0`, nhưng `codex.cmd -C <primaryRepo> --version` vẫn bị chặn **`EXIT=1`**.

### 8.2. Chu trình Thực tế: Codex Atomic Config Rewrite $\rightarrow$ Reset DACL $\rightarrow$ `-ReapplyAclOnly`
Trên thư mục tạm mô phỏng đúng ACL Windows thực tế (`CodexSandboxUsers:(OI)(CI)(RX)` kế thừa từ thư mục cha):
1. **Sau khi cài (`Protect-SensitiveFileAcl`):** Cả `auth.json` và `config.toml` ở 2 luồng đều có `AreAccessRulesProtected=True`, `CodexSandboxUsers AllowCount=0`; Win32 `AuthzAccessCheck(CodexSandboxOffline, <lane2>\config.toml)` trả về `GrantedMask=0x00000000`, `Error=5 [ERROR_ACCESS_DENIED]`, `ReadAllowed=False`; `doctor.ps1` báo `[PASS] ... kernel_acl=locked (protected=6/6)`.
2. **Chạy lệnh Codex thật ghi lại `config.toml`:** `codex.exe features enable suppress_model_change_announcements` (và `features disable ...`) $\rightarrow$ `EXIT=0`.
   * **Quan sát thực tế:** `config.toml` bị Windows reset DACL về kế thừa (`AreAccessRulesProtected=False`, `CodexSandboxUsers AllowCount=1`, `Inherited=True`), `AuthzAccessCheck` đổi thành `GrantedMask=0x00120089`, `Error=0`, `ReadAllowed=True`, và `doctor.ps1` phát hiện ngay `[WARN] ... kernel_acl=EXPOSED(1 Allow ACEs on Lane2/config.toml)`.
3. **Khắc phục bằng `setup-dual-lane.ps1 -ReapplyAclOnly`:** `EXIT=0` (~`1.2s`), khóa lại toàn bộ `7` tệp nhạy cảm (`auth.json`, `config.toml`, `config.backup.toml`, `.rollback/latest.json`, `.rollback/snapshot-*.json`), **giữ nguyên 100% SHA-256** (`SHA_MATCH=True`), `AuthzAccessCheck` trở lại `Error=5 (ReadAllowed=False)` và `doctor.ps1` trở lại `[PASS] kernel_acl=locked (protected=6/6)`.

### 8.3. Kiểm chứng Thực tế Sandbox Đọc/Ghi & Giới hạn Trung thực theo Backend
* **Cú pháp CLI (`codex-cli 0.171.0-alpha.13`):** `codex.exe sandbox --help` (`EXIT=0`) cung cấp `Usage: codex sandbox [OPTIONS] [COMMAND]...` (chỉ có subcommand `uninstall`, `help` — **không có** subcommand `windows`).
* **Kiểm chứng sống trong Windows Sandbox không nâng quyền (`codex.exe sandbox -P lane2_ws -C <worktree>` với `network.enabled = false`):**
  * Tiến trình con chạy dưới restricted token (`IsTokenRestricted=True`, `TokenIntegrityLevel=Medium`, SID của user hiện tại kèm restricted capability SIDs).
  * **Chứng minh sống ranh giới ghi cứng cấp OS:**
    * `<repo>-lane2\src\app.txt`: `READ_OK`, **`WRITE_OK`**.
    * `<repo>\src\app.txt` (repo chính của Luồng 1): `READ_OK`, **`WRITE_DENIED` (`PermissionError` errno 13)**.
    * `<lane2>\canary_exposed.txt`, `canary_locked.txt`, `auth.json`: tất cả **`WRITE_DENIED` (`PermissionError` errno 13)**.
  * **Giới hạn đọc trung thực ở chế độ unelevated:** Do token hạn chế ghi không nâng quyền vẫn chạy dưới SID của user hiện tại, tiến trình con vẫn đọc được tệp mà user hiện tại có quyền `(F)`; khi thử cấu hình chặn đọc tường minh trên chế độ unelevated, Codex trả về `EXIT=1`: `windows sandbox failed: Restricted read-only access requires the elevated Windows sandbox backend`.
* **Danh tính Windows Sandbox nâng quyền (`CodexSandboxOffline` thuộc `CodexSandboxUsers`):**
  * **Giới hạn khởi chạy tự động không tương tác:** Chạy `codex.exe sandbox -c windows.sandbox="elevated"` trên một `CODEX_HOME` tạm chưa cấp phát sẽ chờ thiết lập nâng quyền/UAC tương tác (không thể hoàn tất không tương tác nếu không bấm UAC).
  * **Kiểm chứng quyền hiệu lực tầng nhân NTFS (`authz.dll` `AuthzAccessCheck`, `FILE_GENERIC_READ=0x00120089`) cho tài khoản cục bộ `CodexSandboxOffline`:**
    * Tệp canary có ACE kế thừa `CodexSandboxUsers:(I)(RX)`: `GrantedMask=0x00120089`, `Error=0`, **`ReadAllowed=True`**.
    * Tệp canary đã khóa bằng `Protect-SensitiveFileAcl` (2 bước `icacls`) và `<lane2>\auth.json`: `GrantedMask=0x00000000`, `Error=5 [ERROR_ACCESS_DENIED]`, **`ReadAllowed=False`**.
  * **Kết luận phòng thủ đa tầng:** `Protect-SensitiveFileAcl` + `-ReapplyAclOnly` chặn đọc hiệu quả trước danh tính elevated `CodexSandboxOffline`, nhưng không thể chặn đọc dưới backend unelevated cùng user SID — khẳng định tầm quan trọng bắt buộc của **`env_key`** (0 plaintext API key trong `config.toml`) và **`cli_auth_credentials_store = "keyring"`** (0 token nằm trên đĩa trong `auth.json`).

### 8.4. Kiểm toán 0 Rò rỉ Bí mật & Khôi phục Sạch
* Quét toàn bộ `75` tệp sinh ra/sao lưu trong `<lane1>`, `<lane2>`, `<localBin>` (cấu hình, bản backup, manifest rollback, wrapper, rules, `AGENTS.md`) và toàn bộ đầu ra `doctor.ps1` (`EXIT=0`, `11 PASS | 0 FAIL`, `engine_probe=7/7 forbidden` cả 2 luồng, `Rollback Journal: Healthy & complete`) $\rightarrow$ **`0` rò rỉ** đối với cả token canary lẫn `experimental_bearer_token`; xác nhận `env_key` hiện diện đúng trong `config.toml` Luồng 1 và `restore-original.ps1 -SkipPathUpdate` dọn sạch về trạng thái gốc (`EXIT=0`).
