# Local Workstation Security Audit

Skill + prompt để audit bảo mật **máy trạm cá nhân** trên Windows, macOS và Linux.

Không phải audit codebase — đây là checklist có kỷ luật bằng chứng cho việc kiểm tra chính cái máy bạn đang ngồi: mã hoá ổ, credential nằm trên đĩa, cổng đang mở, persistence, browser profile, và token lọt vào repo.

## Nội dung

| File | Dùng để |
|---|---|
| `SKILL.md` | Skill đầy đủ: luật bằng chứng, bảng lệnh 3 OS theo từng phase, neo mức độ, playbook remediation, và bảng bẫy đã cắn thật |
| `PROMPT.md` | Prompt dán thẳng vào agent bất kỳ (không cần skill loader) |
| `commands/local-pc-security-audit.md` | Entry point dạng slash command cho harness đọc `commands/` |

## Cách dùng

**Có skill loader** (Claude Code, Oh My Pi, …): copy `SKILL.md` vào thư mục skill của harness rồi gọi:

```
/local-pc-security-audit
```

**Không có skill loader**: dán nội dung `PROMPT.md` vào agent. Yêu cầu bắt buộc: agent phải có tool shell — nếu không, nó phải dừng và hỏi bạn dán output thay vì mô tả lại checklist.

## Nguyên tắc cốt lõi

- **Read-only mặc định.** Chỉ thay đổi hệ thống khi bạn chọn phương án cho từng finding.
- **Không in secret.** Chỉ ghi tên biến, độ dài, đường dẫn. Lệnh nào có thể in value (`git remote -v`, `git config --get-regexp 'remote.*'`, `manage-bde -status`) phải redact ngay trong pipeline.
- **Mỗi phép đo phải có positive control.** Filter hẹp tạo ra false negative: "không tìm thấy" thường là "tìm sai cách", không phải "không tồn tại".
- **Ba trạng thái, không hai.** *Đã kiểm và sạch* / *đã kiểm và có vấn đề* / **chưa kiểm được** — trạng thái thứ ba không được gộp vào "sạch".
- **Verify bằng trạng thái, không bằng exit code**, và **đo lại sau khi sửa** (tắt service có thể không đóng port; deny ACL chỉ áp handle mới; provisioner có thể tạo lại account).
- **Thứ tự remediation**: revoke credential → siết quyền/ACL → rewrite lịch sử/tắt service.

## Cấu trúc report sinh ra

`docs/security/<YYYY-MM-DD>-local-workstation-security-audit.md` với: metadata · bảng finding xếp theo blast radius (P0→P3) · mỗi finding đủ **Evidence/Fix/Verify/Rollback** · trạng thái khắc phục (đã áp dụng / đã thử và rollback / còn chờ) · kết luận đã bị bác bỏ · giới hạn coverage.

Report chứa IP, hostname, đường dẫn nội bộ ⇒ coi là tài liệu nội bộ, đừng commit vào repo công khai.

## Ghi chú

Skill này được đúc kết từ một phiên audit thật, trong đó 4 kết luận ban đầu phải sửa lại vì false negative. Bảng "Bẫy đã cắn thật" trong `SKILL.md` là phần giá trị nhất — đọc trước khi chạy.
