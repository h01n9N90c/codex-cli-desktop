# Danh sách Kiểm chứng Thực tế (Real Codex Verification Checklist)

> **Tác giả:** Lê Hoàng Ngọc Tươi | **Dự án:** Codex Dual-Lane & Security Kit (Apache License 2.0)  
> Danh sách này giúp bạn (hoặc đội kiểm duyệt an ninh) tự kiểm chứng bằng lệnh thực tế từng cơ chế của bộ kit trước và sau khi cài đặt — không tin mù quáng vào cấu hình tĩnh.

---

## 1. Kiểm chứng Không lưu Plaintext API Key trong `config.toml` & Bản sao lưu

Khi dùng `-ConfigureGateway`, bộ kit dùng thuộc tính `env_key = "CODEX_GATEWAY_API_KEY"` của Codex (đọc từ biến môi trường User) thay vì ghi trực tiếp key vào `config.toml`:

```powershell
# Kiểm tra hoàn toàn không có chuỗi "sk-" hay "experimental_bearer_token" trong config.toml và các bản backup:
Select-String -Path "$env:USERPROFILE\.codex\config*.toml","$env:USERPROFILE\.codex-official\config*.toml" `
    -Pattern "experimental_bearer_token|sk-[A-Za-z0-9]{10,}"
```
* **Kỳ vọng:** Không có kết quả nào (`0` dòng khớp).

---

## 2. Kiểm chứng Thực thi Engine `execpolicy` (Behavioral Check — Không chỉ đọc chuỗi)

Thay vì chỉ kiểm tra file `default.rules` có tồn tại hay không, hãy gọi trực tiếp bộ máy **Starlark Execpolicy (Rust)** của Codex để xác nhận quyết định `"decision":"forbidden"`:

```powershell
codex execpolicy check --rules "$env:USERPROFILE\.codex-official\rules\default.rules" -- php -r "echo 1;"
codex execpolicy check --rules "$env:USERPROFILE\.codex-official\rules\default.rules" -- mshta http://example.invalid
codex execpolicy check --rules "$env:USERPROFILE\.codex-official\rules\default.rules" -- vssadmin delete shadows /all
codex execpolicy check --rules "$env:USERPROFILE\.codex-official\rules\default.rules" -- Start-Process calc.exe
codex execpolicy check --rules "$env:USERPROFILE\.codex-official\rules\default.rules" -- iex "dir"
codex execpolicy check --rules "$env:USERPROFILE\.codex-official\rules\default.rules" -- git push --force
```
* **Kỳ vọng:** Cả 6 lệnh đều trả về JSON có `"decision":"forbidden"`.
* **Giới hạn kỹ thuật cần nhớ:** `prefix_rule` kiểm tra tiền tố lệnh trực tiếp (`argv[0]`). Các lệnh bị bọc gián tiếp qua `powershell -Command "..."` sẽ do lớp **OS Sandbox (`workspace-write` + `network_access = false`)** và **`approval_policy = "on-request"`** kiểm soát.

---

## 3. Kiểm chứng Ngắt mạng Shell Sandbox & Nạp `AGENTS.md`

```powershell
codex debug prompt-input | Select-String -Pattern "Network access is restricted|Static-Analysis-Only"
```
* **Kỳ vọng:** Xuất hiện đồng thời cả hai dòng:
  * `Network access is restricted.`
  * `2. **Static-Analysis-Only Isolation (NEVER Execute Analyzed Samples/Binaries)**`

---

## 4. Kiểm chứng Merge `config.toml` Không phá hủy (Non-Destructive TOML Merge)

Khi chạy lại `setup-dual-lane.ps1`, các mục cấu hình riêng của bạn như `[mcp_servers.*]`, `[tui]`, `[plugins.*]` hoặc `notify` phải được giữ nguyên:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\test-kit.ps1
```

---

## 5. Kiểm chứng Đồng bộ Phiên UPSERT (`INSERT` + `UPDATE`) khi DB đích trống

Chạy bộ unit test tự động để xác nhận `sync-sessions.py` tạo mới (`INSERT`) thành công các phiên `Pinned` ngay cả khi bảng `threads` ở `~/.codex-official/state_*.sqlite` ban đầu hoàn toàn trống (`0` dòng):

```powershell
python -m unittest discover -s .\tests -v
```
* **Kỳ vọng:** `Ran 3 tests ... OK`.

---

## 6. Chọn đúng Ranh giới Phân vùng: Mềm (`AGENTS.md`) vs Cứng (`-UseGitWorktree`)

| Chế độ | Cách kích hoạt | Bản chất kỹ thuật | Khi nào nên dùng |
| :--- | :--- | :--- | :--- |
| **Chế độ A: Chung 1 Worktree** *(Mặc định)* | Chạy `setup-dual-lane.ps1 -RepoPath "D:\my-app"` | **Ranh giới mềm (Prompt Boundary):** Hai luồng phân chia thư mục qua `AGENTS.md` và `DUAL_LANE_BRIDGE.md`, nhưng cùng chia sẻ quyền ghi OS trong thư mục `D:\my-app`. | Khi muốn 2 luồng thấy ngay file mới của nhau trên cùng 1 cây thư mục mà không cần merge nhánh. |
| **Chế độ B: Tách Git Worktree riêng** *(Cưỡng chế cấp OS)* | Thêm cờ **`-UseGitWorktree`** (hoặc `--use-git-worktree` trên macOS/Linux) | **Ranh giới cứng (Hard OS Sandbox Boundary):** Tạo worktree riêng `<repo>-lane2` trên nhánh `dual-lane-2`. Vì `sandbox_mode = "workspace-write"` chỉ cho phép ghi trong `cwd` hiện tại, OS Sandbox của Luồng 2 **vật lý không thể ghi vào thư mục làm việc của Luồng 1**. | Khi cần cưỡng chế phân quyền ghi tuyệt đối ở cấp hệ điều hành giữa 2 agent. |
