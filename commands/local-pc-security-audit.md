Chạy audit bảo mật máy trạm theo skill `.claude/skills/local-workstation-security-audit/SKILL.md`.

Đọc toàn bộ SKILL.md rồi thực hiện tuần tự **Phase 1 → Phase 9**. Luật cứng: read-only mặc định · không in secret (redact trong pipeline) · mỗi phép đo có positive control (filter hẹp = false negative) · phân biệt "đã kiểm sạch" với "chưa kiểm được" · verify bằng state chứ không bằng exit code · đo lại sau mỗi thay đổi · mọi thay đổi có rollback và chỉ thực thi sau khi user chọn phương án cho từng finding.

Thứ tự remediation khi có nhiều lớp: revoke credential → siết quyền/ACL → rewrite lịch sử/tắt service.

Phạm vi/đối tượng bổ sung từ user (nếu có): $ARGUMENTS

Kết thúc bằng: báo lỗi xếp theo blast radius, mỗi finding đủ Evidence/Fix/Verify/Rollback, report ghi vào `docs/security/<YYYY-MM-DD>-local-workstation-security-audit.md` (coi là tài liệu nội bộ, không push remote công khai), và hỏi user chọn phương án trước khi thay đổi hệ thống.
