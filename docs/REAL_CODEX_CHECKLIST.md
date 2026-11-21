# Danh sách Kiểm chứng Thực tế (Real Codex Verification Checklist)

> **Tác giả:** Lê Hoàng Ngọc Tươi | **Dự án:** Codex Dual-Lane & Security Kit (Apache License 2.0)  
> Danh sách này giúp bạn (hoặc đội kiểm duyệt an ninh) tự kiểm chứng bằng lệnh thực tế từng cơ chế bảo vệ, ACL, `execpolicy`, TOML merge, SQLite UPSERT và khôi phục SHA-256 trước và sau khi cài đặt — không tin mù quáng vào cấu hình tĩnh.

---

## 1. Kiểm chứng Không lưu Plaintext API Key trong `config.toml` & Bản sao lưu

Khi dùng `-ConfigureGateway`, bộ kit dùng thuộc tính `env_key = "CODEX_GATEWAY_API_KEY"` của Codex (đọc từ biến môi trường User) thay vì ghi trực tiếp key vào `config.toml`:

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

# Lệnh vô hại phải trả về matchedRules rỗng ([]):
codex execpolicy check --rules $rules -- git status
```
* **Kỳ vọng:** 9 lệnh đầu trả về `"decision":"forbidden"`, 2 lệnh `git push` / `git reset --hard` trả về `"decision":"prompt"`, và `git status` trả về `{"matchedRules":[]}`.
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
* **Ranh giới CI vs. Codex thật:** Bộ test trong `tests/test-kit.ps1` và GitHub Actions CI chạy trên mock CLI để kiểm tra logic/portable nhanh; hãy luôn chạy các lệnh ở Mục 1–4 trên máy bạn với chính binary Codex thật sau khi cài.

**macOS / Linux / WSL (Bash):**
```bash
./scripts/doctor.sh
ls -la ~/.codex/config.toml ~/.codex/auth.json ~/.codex-official/config.toml ~/.codex-official/auth.json 2>/dev/null || true
```
* **Kỳ vọng:** Các tệp cấu hình và xác thực có quyền chỉ chủ sở hữu đọc/ghi (`-rw-------` / `0600`).

---

## 5. Kiểm chứng Merge `config.toml` Không phá hủy & Khôi phục SHA-256

Chạy bộ test tích hợp trên Windows (không đụng tới `~/.codex*` thật của bạn, dùng thư mục tạm cô lập):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\test-kit.ps1
```
* **Kỳ vọng:** Tất cả kiểm tra cú pháp AST, `-DryRun`, TOML merge giữ nguyên `[mcp_servers.*]`/`[tui]`/`[projects.*]`, cô lập `env_key`, UTF-8 không BOM, chống path-traversal và khôi phục khớp mã băm SHA-256 đều báo `[PASS]`.

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
| **Chế độ B: Tách Git Worktree riêng** *(Cưỡng chế cấp OS)* | Thêm cờ **`-UseGitWorktree`** (Windows) hoặc **`--use-git-worktree`** (macOS/Linux/WSL) | **Ranh giới cứng (Hard OS Sandbox Boundary):** Tạo worktree riêng `<repo>-lane2` trên nhánh `dual-lane-2`. Vì `sandbox_mode = "workspace-write"` chỉ cho phép ghi trong `cwd` hiện tại, OS Sandbox của Luồng 2 **vật lý không thể ghi vào thư mục làm việc của Luồng 1**. | Khi cần cưỡng chế phân quyền ghi tuyệt đối ở cấp hệ điều hành giữa 2 agent. |
