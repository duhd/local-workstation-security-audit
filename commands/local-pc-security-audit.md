Chạy audit bảo mật máy trạm theo skill `SKILL.md` trong repo này (hoặc bản đã copy vào thư mục skill của harness).

Đọc toàn bộ `SKILL.md` rồi chạy theo mục *Thứ tự thực thi (full audit)*: Bước 0 (kiểm tra phiên bản) → **thu thập** Phase 1–6 (posture) **song song** Phase 10–17 (attacker-first: danh tính/credential, thực thi code & leo thang, secret trong artifact, kênh tin cậy, năng lực phát hiện, mạng ngoài listener, vật lý/pre-boot, bề mặt AI agent) → **một lượt elevated** cho mọi mục `Access denied` → Phase 7 (xếp mức) → Phase 9 (report) → Phase 8 (triage từng finding với user). Số Phase là tên mục, không phải thứ tự chạy. Không bỏ phase nào; mục không kiểm được thì ghi "chưa kiểm" kèm lý do.

Luật cứng: read-only mặc định · không in secret (redact trong pipeline) · mỗi phép đo có positive control (filter hẹp = false negative) · phân biệt "đã kiểm sạch" với "chưa kiểm được" · verify bằng state chứ không bằng exit code · đo lại sau mỗi thay đổi · mọi thay đổi có rollback và chỉ thực thi sau khi user chọn phương án cho từng finding.

Thứ tự remediation khi có nhiều lớp: revoke credential → siết quyền/ACL → rewrite lịch sử/tắt service.

Phạm vi/đối tượng bổ sung từ user (nếu có): $ARGUMENTS

Kết thúc bằng: báo lỗi xếp theo blast radius, mỗi finding đủ Evidence/Fix/Verify/Rollback, report ghi vào `docs/security/<YYYY-MM-DD>-local-workstation-security-audit.md` (coi là tài liệu nội bộ, không push remote công khai), và hỏi user chọn phương án trước khi thay đổi hệ thống.
