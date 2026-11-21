# Mô hình Bảo vệ 4 Lớp & Cách ly Phân tích tĩnh cho Codex Agent

> **Tác giả:** Lê Hoàng Ngọc Tươi | **Dự án:** Codex Dual-Lane & Security Kit (Apache License 2.0)

Tài liệu này giải thích các rủi ro thực tế khi chạy AI coding agent tự động trên Windows (đặc biệt khi dùng API bên thứ 3 hoặc làm dự án SAST/phân tích mã nguồn) và cách bộ kit này chặn đứng từng rủi ro đó.

---

## 1. Bốn lớp phòng thủ nhiều tầng (Defense-in-Depth) & Ranh giới kỹ thuật thực tế

### Lớp 1: Khóa Sandbox phạm vi Workspace & Cách ly mạng (`sandbox_mode = "workspace-write"` + `network_access = false` + `approval_policy = "on-request"`)
* **Cưỡng chế ở cấp Hệ điều hành (Hard OS Boundary):** Agent chỉ được quyền ghi tự động trong thư mục làm việc hiện tại (`cwd`) và `%TEMP%`. Toàn bộ ổ `C:\`, thư mục hệ thống Windows, và các thư mục `.git/`, `.codex/`, `.agents/`, `.aws/` bên trong dự án bị khóa chỉ-đọc (`read-only`) ở tầng sandbox Windows (`[windows] sandbox = "elevated"`).
* **Chế độ phê duyệt mặc định an toàn (`approval_policy = "on-request"`):** Các thao tác đọc/ghi/test hợp lệ bên trong sandbox chạy tự động; bất kỳ lệnh nào yêu cầu quyền vượt ra ngoài giới hạn sandbox hoặc khớp quy tắc `decision = "prompt"` sẽ bắt buộc chờ người dùng phê duyệt. (Chỉ chuyển sang `never` khi bạn chủ động truyền `-ApprovalPolicy never` cho tác vụ chạy tự động đã cô lập).
* **Ngắt mạng đầu ra mặc định trong Shell Sandbox (`[sandbox_workspace_write] network_access = false`):** Chặn các tiến trình con trong sandbox mở kết nối mạng ra ngoài, trong khi tiến trình Codex ở ngoài vẫn gọi API LLM bình thường.
* **Phân vùng ghi giữa 2 Agent — Ranh giới Mềm vs Ranh giới Cứng (`-UseGitWorktree`):**
  * Nếu 2 luồng chạy chung trên **cùng 1 thư mục dự án**, phân vùng thư mục giữa Luồng 1 và Luồng 2 là **Ranh giới mềm (Prompt Boundary)** qua `AGENTS.md` và `DUAL_LANE_BRIDGE.md`.
  * Nếu cần **cưỡng chế phân quyền ghi ở cấp hệ điều hành giữa 2 luồng**, hãy chạy bộ cài với cờ **`-UseGitWorktree`** (`--use-git-worktree` trên Unix): bộ cài sẽ tạo một Git worktree riêng (`<repo>-lane2`) cho Luồng 2 để sandbox `workspace-write` khóa cứng từng luồng vào cây thư mục riêng biệt.

### Lớp 2: Quản lý Secret bằng `env_key` & Lọc biến môi trường (`[shell_environment_policy]`)
* Khi cấu hình cổng API bên thứ 3 (`-ConfigureGateway`), bộ kit sử dụng thuộc tính **`env_key = "CODEX_GATEWAY_API_KEY"`** (kết hợp nhập ẩn qua `-PromptGatewayApiKey`), **không bao giờ lưu plaintext API key hay `experimental_bearer_token` vào `config.toml` hoặc các file `.backup-*`**.
* Trong `config.toml`:
```toml
[shell_environment_policy]
exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]
```
* Khi agent mở PowerShell/CMD để chạy lệnh build hoặc test, các biến môi trường khớp mẫu nhạy cảm sẽ bị lọc bỏ, không truyền xuống tiến trình shell con.

### Lớp 3: Tường lửa chặn lệnh nguy hiểm & Cách ly phân tích tĩnh (`rules/default.rules`)
Codex kiểm tra file Starlark `rules/default.rules` **trước khi chạy lệnh trực tiếp** (có hiệu lực ngay cả khi bật `approval_policy = "never"`!):
* **Cấm tuyệt đối (`decision = "forbidden"`):**
  * Chống hành vi kiểu ransomware / phá hệ thống: `vssadmin`, `bcdedit`, `wbadmin`, `diskpart`, `format`.
  * Chống cài cắm chạy ngầm (persistence): `schtasks`, `sc`, `sc.exe`, `reg add`, `reg delete`, `reg import`.
  * Chống chạy mẫu độc hại / trình thông dịch / Windows LOLBins (**Static-Analysis-Only Isolation**): `php`/`php.exe`, `ruby`/`ruby.exe`, `perl`/`perl.exe`, `cscript`/`wscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `msiexec`, `wmic`, `Start-Process`, `Invoke-Expression`, `iex`.
  * Chống xóa lịch sử GitHub: `git push --force`, `git push -f`.
* **Bắt buộc người dùng xác nhận (`decision = "prompt"`):**
  * `git push`, `git reset --hard`, `git clean`.
* *Lưu ý giới hạn kỹ thuật:* `prefix_rule` kiểm khớp theo tiền tố lệnh trực tiếp (`argv[0]`), không phân tích hết mọi chuỗi lồng trong `powershell -Command "..."`. Vì vậy an toàn thực sự đến từ việc kết hợp đồng thời cả **4 lớp** (OS sandbox + ngắt mạng sandbox + `default.rules` + `AGENTS.md`) cùng Windows Defender.

### Lớp 4: Chỉ thị chống Prompt Injection & Phân tích tĩnh bắt buộc (`AGENTS.md` toàn cục)
* Ép mô hình coi mọi nội dung tệp, chuỗi trong file nhị phân, comment, log là **dữ liệu không tin cậy**, không bao giờ thực thi mệnh lệnh giấu trong dữ liệu.
* **Cách ly phân tích tĩnh (`Static-Analysis-Only Isolation`):** Cấm tuyệt đối chạy bất kỳ tệp mẫu nhị phân (`.exe`, `.dll`, `.elf`, `.so`, `.bin`) hay tệp mẫu lỗ hổng (`.php`, `.vbs`, `.hta`, payload `.js`/`.py`); chỉ được đọc/phân tích tĩnh qua parser/disassembler/unit test của dự án.
* Cấm tự ý đọc/in `~/.codex/config.toml`, `~/.codex/auth.json`, `.ssh/`, hồ sơ trình duyệt, hoặc `.env`.

---

## 2. Nguyên tắc "Khiên Git" (Bắt buộc trước mỗi đợt chạy dài)

Trước khi giao cho agent chạy tự động nhiều pha (hoặc chạy qua đêm):
```powershell
git add -A
git commit -m "checkpoint: truoc khi chay agent"
git push
```
Sau khi agent chạy xong, nếu phát hiện sửa sai hoặc không ưng ý:
```powershell
git diff --stat              # Xem nhanh những file đã bị sửa
git reset --hard HEAD        # Quay về trạng thái sạch ban đầu trong 0.1 giây
```

---

## 3. Phân biệt rủi ro thật vs "hoảng loạn nhầm" khi dùng cổng API bên thứ 3

| Tình huống | Bản chất kỹ thuật | Cách xử lý chuẩn |
| :--- | :--- | :--- |
| Thấy AI tự nhiên nhả ra 1 cụm chữ tiếng Trung lạ (vd quảng cáo SEO/game bài) trong khung chat | Có thể là **Glitch Token / Training Data Artifact** từ dữ liệu Common Crawl hoặc bộ lọc/quảng cáo của cổng relay trung gian — **không tự biến thành mã độc/ransomware trên Windows** nếu không chạy lệnh độc hại | 1. Tìm chuỗi đó trong repo (`git diff`, `git log -S`).<br>2. Kiểm tra Windows Defender (`Get-MpComputerStatus`) & Startup Registry.<br>3. Nếu không muốn tiếp tục dùng gateway, khôi phục `config.backup.toml` và xóa key. |
| Lo ngại cổng relay đọc trộm mã nguồn | **Rủi ro có thật về quyền riêng tư:** Cổng trung gian bên thứ 3 có thể lưu log prompt/code gửi qua họ | **Tách việc theo độ nhạy cảm:**<br>- Code thuần kỹ thuật/mã nguồn mở/thuật toán chung $\rightarrow$ có thể tận dụng Luồng 1.<br>- Code chứa bí mật, mật khẩu, tài sản nhạy cảm $\rightarrow$ chạy **Luồng 2 (Tài khoản OpenAI chính chủ)**, không bao giờ đưa `.env` hay secret thật vào repo. |
| Windows Defender báo cảnh báo mã độc (vd `Backdoor:PHP/...`) trên tệp `~/.codex/sessions/.../rollout-*.jsonl` khi làm việc với dự án SAST/an ninh | **Cảnh báo nhầm (False Positive) phổ biến trên log hội thoại:** Khi agent đọc tĩnh file unit test chứa chuỗi mô phỏng webshell/payload, Codex ghi nguyên văn nội dung text đó vào log `.jsonl`, khiến trình diệt virus bắt nhầm chữ ký tĩnh — **không phải agent chạy mã độc** | 1. Kiểm tra `Get-MpThreatDetection` để chắc chắn tài nguyên bị báo là `.jsonl` (log text), không phải `.exe`/`.php` đang chạy.<br>2. Đảm bảo `network_access = false`, `default.rules` chặn LOLBins/interpreter và `AGENTS.md` quy định chỉ phân tích tĩnh.<br>3. Không bấm Quarantine đè lên file `.jsonl` đang chạy nếu muốn giữ phiên hiện tại; hoặc chuyển sang phiên `/new` mới trước khi dọn log cũ. |
| Muốn quay về cấu hình Codex gốc ngay lập tức | File `setup-dual-lane.ps1` luôn lưu bản gốc tại `~/.codex/config.backup.toml` trước khi sửa | Copy `config.backup.toml` đè lại `config.toml` và khởi động lại Codex Desktop. |
