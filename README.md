# Codex Dual-Lane & Security Kit (Windows / macOS / Linux / WSL)

> **Tác giả:** **Lê Hoàng Ngọc Tươi** | **Giấy phép:** Apache License 2.0 ([LICENSE](LICENSE) · [NOTICE](NOTICE))  
> **Bộ công cụ cài đặt 1 chạm, tự thích nghi cấu hình từng máy** giúp chạy song song **2 luồng OpenAI Codex độc lập** — tách tài khoản/API key, dùng chung bộ nhớ & lịch sử, **cách ly chỉ phân tích tĩnh (`Static-Analysis-Only`) & mặc định khóa mạng shell sandbox**, tương thích cả máy **1 ổ đĩa (`C:\`) lẫn nhiều ổ đĩa**, tự dò mọi kiểu cài đặt Codex (`WindowsApps`, `npm`, standalone), **không hardcode model/tier, không mock data, không chứa API key**.

---

## Bạn thuộc trường hợp nào? (Chọn đúng kịch bản của bạn)

| Trường hợp của bạn | Vấn đề bạn đang gặp | Bộ kit này giải quyết thế nào? |
| :--- | :--- | :--- |
| **1. Có cả tài khoản OpenAI chính chủ lẫn key/gateway bên thứ 3** | Muốn vừa dùng Desktop App (chạy key/gateway riêng) vừa dùng CLI (tài khoản ChatGPT/OpenAI chính chủ), nhưng đăng nhập bên này lại đè mất `auth.json` và `config.toml` của bên kia. | Tách 2 `CODEX_HOME` độc lập (`~/.codex` và `~/.codex-official`), sinh sẵn 2 lệnh riêng trên Terminal: **`codex`** *(chính chủ)* và **`codex-t3`** *(cổng phụ)*. |
| **2. Muốn chạy 2 agent song song trên cùng 1 dự án mà vẫn hiểu nhau** | Ví dụ: Luồng 1 làm Backend/Binary, Luồng 2 làm SAST/Frontend/CLI. Chạy chung thì đè file nhau; tách riêng thì không hiểu bên kia đang làm gì. | Nối **NTFS Directory Junction** (Windows) / **symlink** (macOS/Linux) cho `memories`, `sessions`, `skills`, `plugins` để dùng chung bộ não + cơ chế **Ghi riêng – Đọc chung** qua `DUAL_LANE_BRIDGE.md`. |
| **3. Máy chỉ có 1 ổ `C:\`, cấu hình khác nhau hoặc dùng Codex bản `npm`/standalone** | Các script cứng đường dẫn `D:\`, `E:\` hay khóa cứng tên model gói Pro (`gpt-6-astra` / `priority`) sẽ lỗi trên máy khác hoặc tài khoản Plus/API khác. | Tự dò thực tế mọi nguồn cài đặt (`WindowsApps`, `PATH`, `npm`, `-CodexPath`), tự dò feature flags bằng `codex features list`, để trống model mặc định (dùng đúng model thật của tài khoản bạn), tự kiểm tra ổ đĩa NTFS & dung lượng trống. |
| **4. Dự án Rust bị kẹt `Blocking waiting for file lock` khi 2 agent cùng test** | Hai agent cùng chạy `cargo test` tranh nhau khóa `target/.cargo-lock`. | Tự tách `CARGO_TARGET_DIR` riêng cho Luồng 2 (mặc định `%TEMP%\codex-lane2-target`, tùy chỉnh được qua `-CargoTargetDir` nếu ổ `C:` ít dung lượng) $\rightarrow$ biên dịch song song không bao giờ khóa nhau. |
| **5. Dùng CLI từ Windows Desktop gặp lỗi `--no-daemon`, mất task ghim (`Pinned`), hoặc lo mã độc / Prompt Injection** | Báo lỗi `this CLI has no complete local package`, mất danh sách `Pinned`, hỏi duyệt từng lệnh, hoặc lo lộ secret/chạy lệnh phá máy. | Tự động tắt `daemon_auto_start = false` khi có hỗ trợ, kèm `sync-sessions.py` tự đọc schema SQLite thật (`PRAGMA table_info`) để đồng bộ `Pinned` & `Goals`, và cài sẵn **4 lớp bảo vệ** (`workspace-write`, lọc `*KEY*/*TOKEN*`, tường lửa `default.rules`, `AGENTS.md` chống Prompt Injection). |

---

## Kiến trúc "2 Luồng – 1 Bộ Não Chung"

```mermaid
flowchart LR
    subgraph L1["LUỒNG 1 (~/.codex) — Desktop App / codex-t3"]
        A1["config.toml & auth.json riêng<br/>(Cổng phụ hoặc API riêng)"]
        B1["Build Cargo: target/ mặc định"]
        C1["Chỉ GHI vào vùng sở hữu của Luồng 1"]
    end

    subgraph L2["LUỒNG 2 (~/.codex-official) — Lệnh codex (Chính chủ)"]
        A2["config.toml & auth.json riêng<br/>(Tài khoản ChatGPT / OpenAI chính chủ)"]
        B2["Build Cargo: CARGO_TARGET_DIR riêng"]
        C2["Chỉ GHI vào vùng sở hữu của Luồng 2"]
    end

    subgraph SHARED["PHẦN DÙNG CHUNG (NTFS Junction / Symlink + Bridge)"]
        S1["memories/, memories_v2/,<br/>sessions/, archived_sessions/, skills/, plugins/"]
        S2["DUAL_LANE_BRIDGE.md<br/>(Hợp đồng dữ liệu chung — Đọc chéo)"]
    end

    L1 <-->|"Đồng bộ ngữ cảnh & bộ nhớ"| SHARED
    L2 <-->|"Đồng bộ ngữ cảnh & bộ nhớ"| SHARED
```

---

## Đảm bảo tương thích thực tế trên mọi cấu hình máy (Zero Mock Data)

* **Tương thích mọi bố cục ổ đĩa:** Hoạt động mượt trên cả laptop **chỉ có 1 ổ `C:\`** lẫn PC nhiều ổ (`C:\`, `D:\`, `E:\`). Tự động kiểm tra định dạng NTFS và báo cảnh báo nếu ổ build còn dưới 10 GB trống (cho phép chỉ định `-CargoTargetDir` sang bất kỳ ổ nào).
* **Tương thích mọi cách cài đặt Codex:** Tự dò theo thứ tự: `-CodexPath` $\rightarrow$ `WindowsApps` (`OpenAI.Codex`) $\rightarrow$ `PATH` *(tự loại trừ wrapper của chính nó để tránh lặp vô hạn)* $\rightarrow$ `%APPDATA%\npm\codex.cmd` / `%LOCALAPPDATA%\Programs\Codex\codex.exe`.
* **Tương thích mọi phiên bản Codex & mọi gói tài khoản:**
  * Không hardcode model hay `service_tier` vào `config.toml` trừ khi bạn truyền `-OfficialModel` / `-OfficialServiceTier` — tránh lỗi trên tài khoản không có model đó.
  * Tự chạy `codex features list` thật để chỉ bật các flag mà phiên bản Codex trên máy bạn thực sự hỗ trợ.
  * `sync-sessions.py` tự dò file `state_*.sqlite` và `goals_*.sqlite` mới nhất + đọc cột thật qua `PRAGMA table_info`, tương thích ngược/xuôi khi Codex nâng cấp database.
* **An toàn tuyệt đối khi chạy thử & cài đè:** Luôn sao lưu bản gốc có dấu thời gian (`.backup-yyyyMMdd-HHmmss`), giữ lại toàn bộ `[projects]` đã `trusted` từ trước, và hỗ trợ **`-DryRun`** để xem trước toàn bộ thao tác mà không sửa 1 byte nào trên đĩa!

---

## Cấu trúc thư mục

```text
codex-cli-desktop-/
├── README.md                     # Hướng dẫn tổng hợp (file bạn đang đọc)
├── LICENSE                       # Giấy phép Apache License 2.0
├── NOTICE                        # Khai báo bản quyền tác giả (Apache-2.0)
├── SECURITY.md                   # Chính sách bảo mật & báo cáo lỗ hổng (tab Security trên GitHub)
├── .gitignore                    # Chặn tuyệt đối không commit key / auth.json / config.toml
├── scripts/
│   ├── setup-dual-lane.ps1       # Bộ cài đặt tự thích nghi cho Windows 10/11 (hỗ trợ -DryRun)
│   ├── setup-dual-lane.sh        # Bộ cài đặt tương đương cho macOS / Linux / WSL (hỗ trợ --dry-run)
│   ├── doctor.ps1                # Chẩn đoán hệ thống thực tế cho Windows (read-only, zero mock data)
│   ├── doctor.sh                 # Chẩn đoán hệ thống thực tế cho macOS / Linux / WSL (read-only)
│   └── sync-sessions.py          # Đồng bộ phiên, mục đã ghim (Pinned) & Goals (SQLite read-only nguồn)
├── templates/
│   ├── default.rules             # Tường lửa chặn lệnh nguy hiểm & LOLBins (Starlark execpolicy)
│   ├── AGENTS.lane1.md           # Chỉ thị bảo vệ, phân tích tĩnh & phân luồng cho Luồng 1
│   ├── AGENTS.lane2.md           # Chỉ thị bảo vệ, phân tích tĩnh & phân luồng cho Luồng 2
│   └── DUAL_LANE_BRIDGE.md       # Mẫu cầu nối giao tiếp 2 luồng cho bất kỳ dự án nào
└── docs/
    ├── GUIDE_AND_MANIFEST.md     # Hướng dẫn chi tiết, khai báo từng tệp/hàm/tham số & cách gỡ an toàn
    ├── SECURITY_MODEL.md         # Chi tiết 4 lớp bảo vệ, cách ly phân tích tĩnh & Khiên Git
    └── TROUBLESHOOTING.md        # Sổ tay xử lý 7 lỗi thực chiến hay gặp nhất
```

---

## Hướng dẫn cài đặt nhanh (Windows — 3 bước)

### Bước 0 *(Khuyên làm trước)* — Tải kho & chạy thử `-DryRun` để kiểm tra máy của bạn
Mở PowerShell và chạy (chế độ `-DryRun` không sửa bất kỳ file nào):
```powershell
git clone https://github.com/h01n9N90c/codex-cli-desktop-.git
cd codex-cli-desktop-
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 `
    -RepoPath "C:\Projects\my-app" `
    -DryRun
```

### Bước 1 — Chạy cài đặt chính thức (chọn đúng kịch bản của bạn)

#### Kịch bản A: Cài chuẩn cho máy 1 ổ `C:\` hoặc nhiều ổ (dùng model mặc định của tài khoản)
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 `
    -RepoPath "C:\Projects\my-app" `
    -InstallBridgeTemplate
```

#### Kịch bản B: Cài kèm chọn model cụ thể + kéo sẵn các phiên đã ghim (`Pinned`) từ Desktop sang CLI
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 `
    -RepoPath "C:\Projects\my-app" `
    -OfficialModel "gpt-6.2-sol" `
    -SyncSessions `
    -InstallBridgeTemplate
```

#### Kịch bản C: Có thêm cổng API trung gian (bên thứ 3) cho Luồng 1
> **Bảo mật:** Không bao giờ lưu API key trực tiếp vào file trong repo; chỉ truyền qua tham số lúc chạy.
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 `
    -RepoPath "C:\Projects\my-app" `
    -ConfigureGateway `
    -GatewayBaseUrl "https://<cong-api-cua-ban>/v1" `
    -GatewayModel "<ten-model>" `
    -GatewayApiKey "<API_KEY_CUA_BAN>" `
    -InstallBridgeTemplate
```

*(Nếu ổ `C:\` của bạn ít dung lượng trống và máy có ổ khác cho dự án Rust, thêm tham số `-CargoTargetDir "D:\codex-lane2-target"`).*

### Bước 2 — Đăng nhập tài khoản OpenAI / ChatGPT chính chủ cho Luồng 2 (1 lần duy nhất)
```powershell
codex login
codex login status   # Kỳ vọng: Logged in using ChatGPT
```

### Bước 3 — Kiểm tra sức khỏe toàn hệ thống bằng `doctor.ps1` & bắt đầu chạy
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\doctor.ps1
```
Sau khi toàn bộ mục báo `[PASS]`:
* **Luồng 1:** Mở **Codex Desktop App** *(hoặc gõ `codex-t3` trên Terminal)*.
* **Luồng 2 (Chính chủ):** Mở PowerShell trong thư mục dự án và gõ `codex` *(hoặc `codex resume` để mở lại phiên đã ghim)*.

---

## Người dùng macOS / Linux / WSL
```bash
git clone https://github.com/h01n9N90c/codex-cli-desktop-.git
cd codex-cli-desktop-
chmod +x ./scripts/setup-dual-lane.sh ./scripts/doctor.sh
./scripts/setup-dual-lane.sh --repo /path/to/your-project --dry-run
./scripts/setup-dual-lane.sh --repo /path/to/your-project --install-bridge
./scripts/doctor.sh
codex login
codex
```

---

## Sổ tay lệnh nhanh hàng ngày

| Mục đích | Lệnh |
| :--- | :--- |
| Chẩn đoán thực tế cấu hình máy & trạng thái 2 luồng | `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\doctor.ps1` |
| Chạy Codex CLI bằng **tài khoản OpenAI chính chủ (Luồng 2)** | `codex` *(hoặc `codex-official`)* |
| Chạy Codex CLI bằng **cấu hình Desktop / Gateway (Luồng 1)** | `codex-t3` |
| Đổi model ngay trong khung chat TUI | Gõ `/model` |
| Mở CLI với một model cụ thể | `codex -m <model-slug>` |
| Mở lại phiên cũ / phiên đã ghim | `codex resume` *(hoặc `codex resume --all`)* |
| Đồng bộ lại phiên mới ghim từ Desktop sang CLI | `python .\scripts\sync-sessions.py --repo "C:\Projects\my-app"` |
| Chỉnh chế độ hỏi duyệt ngay trong phiên đang mở | Gõ `/permissions` |
| Gặp giới hạn 100 request/phiên từ cổng trung gian | Gõ `/new` *(code trên đĩa còn nguyên, không bấm Hoàn tác)* |

---

## Tài liệu chi tiết đi kèm
* 📘 **[Hướng dẫn Chi tiết & Khai báo Mã nguồn / Công cụ (Manifest)](docs/GUIDE_AND_MANIFEST.md)** — Khai báo minh bạch từng tệp, từng hàm mã nguồn, đường dẫn đọc/ghi, toàn bộ bảng tham số CLI và hướng dẫn gỡ bỏ an toàn 100%.
* 🛡️ **[Mô hình Bảo vệ 4 Lớp, Cách ly Phân tích tĩnh & Khiên Git](docs/SECURITY_MODEL.md)**
* 🔧 **[Cẩm nang Xử lý 7 Lỗi Thực Chiến](docs/TROUBLESHOOTING.md)**

---

## Tác giả & Bản quyền
* **Tác giả:** **Lê Hoàng Ngọc Tươi**
* **Bản quyền & Giấy phép:** Phát hành theo giấy phép mã nguồn mở **[Apache License 2.0](LICENSE)** (`Copyright 2026 Lê Hoàng Ngọc Tươi` — xem thêm [NOTICE](NOTICE)). Mọi người có thể tự do sử dụng, sửa đổi và phân phối lại theo điều khoản Apache-2.0 với điều kiện giữ nguyên tệp `LICENSE` và thông báo bản quyền `NOTICE`.
