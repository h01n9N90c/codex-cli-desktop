# Mô hình Bảo vệ 4 Lớp, Ranh giới Thực tế & Cách ly Phân tích tĩnh cho Codex Agent

> **Tác giả:** Lê Hoàng Ngọc Tươi | **Dự án:** Codex Dual-Lane & Security Kit (Apache License 2.0)

Tài liệu này giải thích các rủi ro thực tế khi chạy AI coding agent trên Windows, macOS, Linux và WSL (đặc biệt khi dùng API bên thứ 3 hoặc làm dự án SAST/phân tích nhị phân), cách bộ kit xây dựng phòng thủ 4 lớp, **ranh giới trung thực giữa điều bộ kit đảm bảo và giới hạn của hệ điều hành / Codex runtime**, cũng như quy trình khôi phục an toàn.

---

## 1. Minh bạch hóa Ranh giới An ninh: Bộ Kit Đảm bảo gì vs. Giới hạn OS / Codex Runtime

Để đánh giá rủi ro chính xác và không tạo cảm giác an toàn giả, bảng dưới tách rõ những gì bộ kit **thực sự kiểm soát được** so với những giới hạn vốn có của Hệ điều hành và Codex runtime:

| Khía cạnh | Điều bộ Kit **ĐẢM BẢO** | Giới hạn thực tế của **OS / Codex Runtime** & Cách khắc phục |
| :--- | :--- | :--- |
| **Cách ly 2 `CODEX_HOME` & Secret trong `config.toml`** | Tách hoàn toàn `~/.codex` (Luồng 1) và `~/.codex-official` (Luồng 2); không bao giờ ghi plaintext API key hay `experimental_bearer_token` vào `config.toml` hoặc các file `.backup-*` (dùng `env_key`). | Nếu bạn chủ động dán key vào prompt hoặc file repo thì LLM vẫn thấy text đó. Hãy giữ secret ngoài repo và ưu tiên `cli_auth_credentials_store = "keyring"` + `env_key`. |
| **Quyền đọc NTFS trên `~/.codex*` (Windows)** | `setup-dual-lane.ps1` chạy quy trình **2 bước `icacls.exe` fail-closed** (`/inheritance:d` rồi `/remove:g "CodexSandboxUsers"`, hậu kiểm `AreAccessRulesProtected` + `0` Allow ACE; báo lỗi dừng ngay nếu khóa ACL thất bại) trên `auth.json`, `config.toml`, bản sao lưu và manifest `.rollback/`; hỗ trợ cờ **`-ReapplyAclOnly`** để khóa nhanh lại trong 1 giây; tự bỏ qua bước 2 trên máy mới chưa có nhóm `CodexSandboxUsers`. | 1. Khi sandbox Windows của Codex khởi tạo, Codex có thể gắn quyền kế thừa **`CodexSandboxUsers:(OI)(CI)(RX)`** lên thư mục `~/.codex*` để tiến trình sandbox đọc tài nguyên cần thiết.<br>2. **Giới hạn atomic replace không thể chặn từ bên ngoài:** Script ngoài **không thể tự ngăn** `codex.exe` hay Codex Desktop reset DACL tệp khi Codex chạy `codex features ...`, sửa Settings trên App, hoặc tạo lại `auth.json` theo kiểu ghi tệp tạm rồi đổi tên (tệp mới sẽ nhận lại quyền kế thừa từ thư mục cha).<br>3. **Ranh giới kiểm tra của `doctor.ps1`:** `doctor.ps1` chạy dưới quyền user hiện tại để kiểm tra tĩnh DACL trên host (`host_dacl`) và cấu trúc `.sandbox\deny_read_acl_state.json`, chứ không tự sinh token con dưới danh tính `CodexSandboxOffline` (để kiểm thử thực thi trực tiếp từ token sandbox, dùng quy trình trong [REAL_CODEX_CHECKLIST.md](REAL_CODEX_CHECKLIST.md)).<br>👉 **Khuyến nghị mạnh nhất:** Dùng `env_key` (không lưu key trong `config.toml`) và bật **`cli_auth_credentials_store = "keyring"`** (khi bản Codex hỗ trợ) để lưu OAuth token trong OS Keyring thay vì tệp `auth.json`; dùng `setup-dual-lane.ps1 -ReapplyAclOnly` + `doctor.ps1` sau khi sửa cấu hình Codex. |
| **Tường lửa lệnh Starlark (`rules/default.rules`)** | Chặn cứng (`forbidden`) trực tiếp lệnh phá hệ thống, persistence, sửa ACL/mạng, force-push, trình thông dịch corpus & LOLBins (kèm biến thể `.exe`/`.com`/chữ thường) ngay cả khi `approval_policy = "never"`. | `prefix_rule` chỉ khớp chính xác tiền tố token trực tiếp (`argv[0]`, `argv[1]`, ...), **không phân tích sâu** mọi chuỗi lệnh lồng trong `powershell -Command "..."`, `cmd /c "..."` hay `bash -c "..."`. Vì vậy bắt buộc phải giữ đồng thời cả 4 lớp (OS Sandbox + `network_access = false` + `approval_policy = "on-request"` + `AGENTS.md`). |
| **Phân vùng ghi giữa Luồng 1 và Luồng 2** | Cung cấp cả cầu nối `DUAL_LANE_BRIDGE.md` lẫn tùy chọn **`-UseGitWorktree`** / **`--use-git-worktree`**; khi bật worktree, wrapper Luồng 2 (`codex`, `codex-official`) tự động chuyển `cwd` từ thư mục gốc dự án **lẫn mọi thư mục con** sang nhánh thư mục tương ứng trong worktree Luồng 2 và chặn `-C` / `--cd` / `--add-dir` trỏ ngược về repo chính. | Khi 2 luồng chạy trên **cùng 1 thư mục làm việc**, phân vùng file chỉ là **Ranh giới mềm (Soft Prompt Boundary)**. Ngay cả khi bật `-UseGitWorktree`, các trường hợp đặc biệt như gắn nhiều thư mục qua giao diện Codex Desktop hoặc ghi đè cấu hình `--config` phức tạp vẫn cần kiểm thử trực tiếp trên phiên bản Codex Desktop/CLI đang cài (CI xanh với mock binary không chứng minh mọi cấu hình Codex Desktop thật). |
| **Rollback & Quyền POSIX trên Unix (`restore-original.*`)** | Lưu manifest giao dịch SHA-256 (`.rollback/latest.json` / `.rollback/latest.tsv`), sao lưu cả launcher có sẵn trước khi cài, lưu & khôi phục chính xác chế độ POSIX 3 chữ số octal (`000`–`777` ở cột 5 TSV trên Unix, vd `0755`/`0644`/`0600`) và từ chối bit đặc biệt (`SUID`/`SGID`). | Trên Windows NTFS, quyền truy cập do ACL đảm nhận (không dùng bit POSIX). Trên Unix, rollback khôi phục nội dung khớp SHA-256 và bit quyền chuẩn `000`–`777`, không khôi phục `xattr`, `mtime` hay quyền sở hữu chéo user. |
| **Dùng chung Bộ nhớ & Lịch sử (`Junction` / `symlink`)** | Liên kết `memories`, `memories_v2`, `sessions`, `archived_sessions`, `skills`, `plugins` để 2 luồng hiểu ngữ cảnh của nhau; `restore-original.*` luôn tháo liên kết trước khi xóa thư mục để không mất dữ liệu gốc. | Vì log hội thoại (`.jsonl`) và `memories/` dùng chung, thông tin từng trao đổi ở Luồng 1 cũng tồn tại trên đĩa chung với Luồng 2. Không đặt bí mật thật vào khung chat, và tách các dự án tuyệt mật sang Luồng 2 (OpenAI chính chủ) thay vì đi qua cổng API bên thứ 3. |

---

## 2. Bốn lớp phòng thủ nhiều tầng (Defense-in-Depth)

### Lớp 1: Khóa Sandbox phạm vi Workspace & Cách ly mạng (`sandbox_mode = "workspace-write"` + `network_access = false` + `approval_policy = "on-request"`)
* **Cưỡng chế ở cấp Hệ điều hành (Hard OS Boundary):** Agent chỉ được quyền ghi tự động trong thư mục làm việc hiện tại (`cwd`) và thư mục tạm (`%TEMP%` / `/tmp`). Toàn bộ ổ hệ thống (`C:\`, `/etc`, ...) và các thư mục nhạy cảm như `.git/`, `.codex/`, `.agents/` được bảo vệ bởi tầng sandbox của Codex (`[windows] sandbox = "elevated"` trên Windows; Seatbelt/Landlock trên macOS/Linux).
* **Chế độ phê duyệt mặc định an toàn (`approval_policy = "on-request"`):** Các thao tác đọc/ghi/test hợp lệ bên trong sandbox chạy tự động; bất kỳ lệnh nào yêu cầu thoát sandbox hoặc chạm quy tắc `decision = "prompt"` đều bắt buộc chờ người dùng phê duyệt. Chỉ dùng `-ApprovalPolicy never` / `--approval-policy never` khi bạn chủ động chạy tác vụ tự động trong môi trường đã cô lập và đã có checkpoint Git.
* **Ngắt mạng đầu ra mặc định trong Shell Sandbox (`[sandbox_workspace_write] network_access = false`):** Chặn tiến trình con trong shell sandbox mở kết nối mạng ra ngoài (chống exfiltration dữ liệu và tải payload), trong khi tiến trình Codex ở ngoài vẫn gọi API LLM bình thường.
* **Phân vùng ghi giữa 2 Agent — Ranh giới Mềm vs. Ranh giới Cứng (`-UseGitWorktree` / `--use-git-worktree`):**
  * **Chung 1 thư mục dự án (mặc định):** Ranh giới mềm (Prompt Boundary) qua `AGENTS.md` và `DUAL_LANE_BRIDGE.md`.
  * **Tách Git Worktree riêng (`-UseGitWorktree` / `--use-git-worktree`):** Tạo worktree riêng `<repo>-lane2` cho Luồng 2 để sandbox `workspace-write` khóa cứng từng luồng vào cây thư mục độc lập.

### Lớp 2: Quản lý Secret (`env_key` & `keyring`), Lọc biến môi trường & Khóa Quyền Tệp (NTFS ACL / POSIX)
* **Không lưu plaintext API key trong `config.toml`:** Khi cấu hình cổng API bên thứ 3 (`-ConfigureGateway`), bộ kit chỉ ghi thuộc tính **`env_key = "CODEX_GATEWAY_API_KEY"`** (kết hợp nhập ẩn qua `-PromptGatewayApiKey` bằng `Read-Host -AsSecureString`), **tuyệt đối không ghi plaintext key hay `experimental_bearer_token` vào `config.toml` hoặc các tệp `.backup-*`**.
* **Khuyến nghị vệ sinh mật khẩu/token mức cao nhất (`keyring` + `env_key`):**
  * Để tránh lưu OAuth token dạng tệp văn bản trong `auth.json`, hãy cân nhắc bật trong `config.toml` (khi phiên bản Codex của bạn hỗ trợ):
    ```toml
    cli_auth_credentials_store = "keyring"
    ```
  * Khi kết hợp `cli_auth_credentials_store = "keyring"` cho tài khoản đăng nhập và `env_key` cho cổng API bên thứ 3, ngay cả khi DACL tệp `config.toml` bị reset sau lần ghi đè atomic của Codex, tệp vẫn không chứa secret dạng rõ.
* **Lọc biến môi trường sang shell con (`[shell_environment_policy]`):**
  ```toml
  [shell_environment_policy]
  exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]
  ```
  Khi agent mở PowerShell/CMD/Bash chạy lệnh build hoặc test, các biến môi trường khớp mẫu nhạy cảm sẽ bị lọc bỏ khỏi tiến trình con.
* **Khóa quyền tệp ở tầng hệ thống tệp:**
  * **Trên macOS / Linux / WSL:** Dùng `umask 077`, `chmod 700` cho thư mục nhạy cảm và `chmod 600` cho `config.toml`, `auth.json`, bản sao lưu và các tệp JSONL đồng bộ.
  * **Trên Windows (Quy trình `icacls.exe` 2 bước):**
    Vì thư mục `~/.codex` có thể mang quyền kế thừa `CodexSandboxUsers:(OI)(CI)(RX)`, việc chỉ chạy `icacls <file> /remove:g "CodexSandboxUsers"` sẽ **không xóa được ACE kế thừa**. Do đó `Protect-SensitiveFileAcl` trong `setup-dual-lane.ps1` chạy **2 lệnh tuần tự**:
    ```cmd
    icacls "<file>" /inheritance:d
    icacls "<file>" /remove:g "CodexSandboxUsers"
    ```
    1. **Bước 1 (`/inheritance:d`):** Tắt kế thừa quyền từ thư mục cha và chuyển các ACE kế thừa thành ACE tường minh (giữ nguyên quyền của chủ sở hữu / `SYSTEM` / `Administrators`, không bao giờ tự khóa quyền chính bạn).
    2. **Bước 2 (`/remove:g "CodexSandboxUsers"`):** Chỉ chạy khi nhóm `CodexSandboxUsers` tồn tại trên máy, gỡ hẳn **Allow ACE** đọc của nhóm sandbox mà không chạm tới bất kỳ Deny ACE bảo vệ nào. Nếu máy mới chưa có nhóm `CodexSandboxUsers`, bước 2 tự động bỏ qua an toàn mà không làm hỏng cài đặt. Ngoài ra `doctor.ps1` chỉ kiểm tra tham khảo (read-only) sự tồn tại của `.sandbox\deny_read_acl_state.json` (không sửa hay in nội dung).
    * *Lưu ý quan trọng về atomic replace:* Như đã nêu ở Mục 1, các lệnh như `codex features enable ...` hoặc chỉnh Settings trong Codex Desktop ghi lại `config.toml` theo kiểu atomic replace nên Windows sẽ cấp lại DACL kế thừa từ thư mục cha. Hãy chạy `.\scripts\doctor.ps1` để kiểm tra chỉ số `kernel_acl` và chạy lại bước khóa ACL sau khi thay đổi cấu hình trong Codex.

### Lớp 3: Tường lửa chặn lệnh nguy hiểm & Cách ly phân tích tĩnh (`rules/default.rules`)
Codex nạp tệp Starlark `rules/default.rules` vào tầng Rust execpolicy **trước khi chạy lệnh trực tiếp** (có hiệu lực ngay cả khi bật `approval_policy = "never"`). Mọi quy tắc đều được chú thích rõ lý do ngay trong `templates/default.rules` kèm các biến thể `.exe`/`.com`/chữ thường:
* **Cấm tuyệt đối (`decision = "forbidden"`):**
  1. **Chống hành vi phá hệ thống / ransomware:** `vssadmin`, `bcdedit`, `wbadmin`, `diskpart`, `format` *(kèm `.exe`/`.com`)*.
  2. **Chống cài cắm persistence & sửa Registry:** `schtasks`, `sc`, `reg add`, `reg delete`, `reg import` *(kèm `.exe`)*.
  3. **Chống hạ cấp NTFS ACL, chiếm quyền sở hữu & phá cấu hình mạng:** `icacls`, `takeown`, `net`, `net1`, `netsh` *(kèm `.exe`)*.
  4. **Chống phá lịch sử Git từ xa:** `git push --force`, `git push -f` *(kèm `git.exe`)*.
  5. **Cách ly phân tích tĩnh (`Static-Analysis-Only Isolation`):**
     * *Trình thông dịch mẫu corpus:* `php`, `ruby`, `perl` *(kèm `.exe`)*.
     * *Windows Script Host, LOLBins & thực thi động:* `cscript`, `wscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `msiexec`, `wmic`, `Start-Process`/`start-process`/`saps`, `Invoke-Expression`/`invoke-expression`/`iex`/`IEX`.
* **Bắt buộc người dùng xác nhận (`decision = "prompt"`):**
  * `git push`, `git reset --hard`, `git clean` *(kèm `git.exe`)*.
* *Lưu ý ranh giới kỹ thuật:* `prefix_rule` kiểm khớp chính xác theo tiền tố lệnh trực tiếp (`argv[0]`), không phân tích hết mọi chuỗi lồng trong `powershell -Command "..."` hay `bash -c "..."`. Vì vậy luôn duy trì đủ cả 4 lớp phòng thủ cùng Windows Defender / AV của máy.

### Lớp 4: Chỉ thị chống Prompt Injection & Phân tích tĩnh bắt buộc (`AGENTS.md` toàn cục)
* Ép mô hình coi mọi nội dung tệp, chuỗi trong file nhị phân, comment, log là **dữ liệu không tin cậy**, không bao giờ làm theo mệnh lệnh ẩn trong dữ liệu.
* **Cách ly phân tích tĩnh (`Static-Analysis-Only Isolation`):** Cấm tuyệt đối thực thi bất kỳ tệp mẫu nhị phân (`.exe`, `.dll`, `.elf`, `.so`, `.bin`) hay tệp mẫu lỗ hổng (`.php`, `.vbs`, `.hta`, payload `.js`/`.py`); chỉ được đọc tĩnh và chạy parser/disassembler/unit test đáng tin cậy của chính dự án.
* Cấm tự ý đọc/in `~/.codex/config.toml`, `~/.codex/auth.json`, `~/.codex-official/`, `.rollback/`, `.ssh/`, hồ sơ trình duyệt, `.env` hoặc biến môi trường chứa secret.

---

## 3. Nguyên tắc "Khiên Git" & Khôi phục Trạng thái An toàn (Safe Rollback)

### 3.1. Tạo Checkpoint Git trước mỗi đợt chạy dài
Trước khi giao cho agent chạy nhiều pha tự động:
```powershell
git add -A
git commit -m "checkpoint: before agent run"
git push
```
Nếu sau khi chạy cần kiểm tra hoặc hoàn tác thay đổi mã nguồn:
```powershell
git diff --stat              # Xem nhanh danh sách tệp bị sửa
git reset --hard HEAD        # Quay về trạng thái checkpoint sạch
```

### 3.2. Khôi phục Cấu hình Bộ Kit An toàn (SHA-256 Verified Rollback)
* **Windows:** Luôn chạy `-DryRun` trước để kiểm tra mã băm SHA-256 và danh sách thao tác, sau đó chạy khôi phục chính thức:
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1 -DryRun
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1
  # Nếu muốn dọn luôn thư mục ~/.codex-official sau khi đã kiểm chứng tháo 6 Junction:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1 -RemoveLane2Home
  ```
* **macOS / Linux / WSL:**
  ```bash
  ./scripts/restore-original.sh --dry-run
  ./scripts/restore-original.sh
  # Hoặc dọn luôn ~/.codex-official sau khi đã gỡ an toàn 6 symlink:
  ./scripts/restore-original.sh --remove-lane2-home
  ```
* **Bảo vệ chống Path Traversal & Bảo vệ Dữ liệu Luồng 1:** Script khôi phục luôn kiểm tra mọi đường dẫn trong manifest nằm trong phạm vi thư mục Codex được phép, xác minh mã băm SHA-256 trước khi ghi đè, và **luôn tháo 6 NTFS Junction / symlink trước** khi thực hiện bất kỳ thao tác xóa thư mục nào để dữ liệu thật trong `~/.codex` không bao giờ bị ảnh hưởng.

---

## 4. Phân biệt rủi ro thật vs. "hoảng loạn nhầm" khi dùng cổng API bên thứ 3

| Tình huống | Bản chất kỹ thuật | Cách xử lý chuẩn |
| :--- | :--- | :--- |
| Thấy AI tự nhiên nhả ra 1 cụm chữ lạ / quảng cáo SEO trong khung chat | Có thể là **Glitch Token / Training Data Artifact** hoặc chuỗi chèn từ cổng relay bên thứ 3 — **không tự biến thành mã độc/ransomware trên Windows** nếu agent không thực thi lệnh độc hại | 1. Kiểm tra diff mã nguồn (`git diff`, `git log -S`).<br>2. Kiểm tra Windows Defender (`Get-MpComputerStatus`) & Startup Registry.<br>3. Nếu muốn ngừng dùng gateway, chạy `restore-original.ps1` (hoặc khôi phục `~/.codex/config.backup.toml`) và xóa biến môi trường key. |
| Lo ngại cổng relay lưu log mã nguồn | **Rủi ro có thật về quyền riêng tư:** Cổng trung gian bên thứ 3 có thể ghi log prompt/code gửi qua máy chủ của họ | **Tách việc theo độ nhạy cảm:**<br>- Code mã nguồn mở / thuật toán chung $\rightarrow$ có thể chạy Luồng 1.<br>- Code chứa bí mật, tài sản độc quyền, thông tin nhạy cảm $\rightarrow$ chạy **Luồng 2 (Tài khoản OpenAI chính chủ)**, không bao giờ đưa `.env` hay secret thật vào repo. |
| Windows Defender báo cảnh báo mã độc (vd `Backdoor:PHP/...`) trên tệp `~/.codex/sessions/.../rollout-*.jsonl` khi làm dự án SAST/an ninh | **Cảnh báo nhầm (False Positive) phổ biến trên log hội thoại:** Khi agent đọc tĩnh tệp test chứa chuỗi giả lập webshell/payload, Codex ghi nguyên văn text đó vào log `.jsonl`, khiến AV bắt chữ ký tĩnh — **không phải agent chạy mã độc** | 1. Kiểm tra `Get-MpThreatDetection` để xác nhận `Resources` chỉ là tệp text `.jsonl`, không phải `.exe`/`.php` đang chạy.<br>2. Xác nhận `network_access = false`, `default.rules` chặn LOLBins/interpreter và `AGENTS.md` bật `Static-Analysis-Only`.<br>3. Không bấm Quarantine lên tệp `.jsonl` đang ghi dở; chuyển sang `/new` trước khi dọn log cũ nếu cần. |
| Muốn quay về cấu hình Codex gốc ngay lập tức | Mọi tệp bị chỉnh sửa đều có bản sao lưu `.backup-yyyyMMdd-HHmmss` tracked trong `.rollback/latest.json` (và riêng `-ConfigureGateway` lưu thêm `~/.codex/config.backup.toml` bản sạch đầu tiên) | Chạy `.\scripts\restore-original.ps1 -DryRun` rồi `.\scripts\restore-original.ps1` (hoặc `./scripts/restore-original.sh` trên Unix) và khởi động lại Codex Desktop. |
