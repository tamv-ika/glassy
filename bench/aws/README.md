> THROWAWAY: công cụ đo của SP0; không dùng cho production.

# S3 — đo XDP/AF_XDP trên ENA

`s3-ena-probe.sh` trả lời câu hỏi S3 trong §11 của spec: trên AWS (driver ENA), node chạy được những mode nào (XDP native/generic, AF_XDP copy/zero-copy), và một chương trình XDP đơn giản đẩy được bao nhiêu pps trước khi đụng các giới hạn `*_allowance_exceeded`.

Với mỗi loại instance (mặc định `c7gn.2xlarge` và `c6in.2xlarge`), script:
1. chạy 2 instance Amazon Linux 2023 (kernel 6.12) trong một cluster placement group: **DUT** (máy được đo) và **GEN** (máy tạo tải);
2. build `spikes/cap-probe` ngay trên instance, rồi chạy nó trên DUT hai lần: lần đầu với cấu hình lúc boot, lần sau khi đã chuẩn bị NIC cho XDP native (MTU 1500, dùng một nửa số channel);
3. gắn `xdp_reflect.o` lên DUT. GEN dùng `pktgen` bắn UDP 64 byte tới port 9 của DUT; script đo delta của `ethtool -S` trên DUT trong 30 giây;
4. ghi kết quả vào `results/<type>-<UTC timestamp>.json`, rồi **xoá toàn bộ resource**: instance, security group, placement group, key pair.

## Chi phí và an toàn

- Mỗi loại instance chạy 2 máy trong khoảng 10–15 phút (phần lớn là thời gian build). Giá on-demand của các loại mặc định vào khoảng 0.4–0.6 USD/giờ mỗi máy, nên **cả lần chạy tốn dưới 1 USD**. Hãy xem lại giá ở region của bạn.
- Mọi resource được ghi lại ngay khi tạo, và bị xoá trong `trap EXIT`, kể cả khi script lỗi giữa chừng hoặc bị Ctrl-C / đóng tab (`tests/test_teardown.sh` kiểm điều này).
- Lưới an toàn: instance tự tắt sau **120 phút** (`shutdown -h` trong user-data, với `instance-initiated-shutdown-behavior=terminate`), phòng khi shell chạy script chết trước khi kịp dọn.
- Mỗi loại instance bị terminate ngay khi đo xong, nên lúc cao điểm chỉ cần quota 16 vCPU (On-Demand Standard).

## Yêu cầu

- **AWS CloudShell** ở region muốn đo. CloudShell có sẵn `aws`, `jq`, `ssh`, `scp`, `curl`, `tar`, và dùng chính credential của console, nên **không cần tạo access key**.
- Account có **default VPC** (script dùng default subnet của AZ được chọn).
- Quyền IAM: `ec2:Describe*`, `ec2:CreateKeyPair`/`DeleteKeyPair`, `ec2:CreateSecurityGroup`/`DeleteSecurityGroup`/`AuthorizeSecurityGroupIngress`, `ec2:CreatePlacementGroup`/`DeletePlacementGroup`, `ec2:RunInstances`/`TerminateInstances`, `ec2:CreateTags`, `ssm:GetParameter`.
- Security group chỉ mở SSH cho IP của CloudShell (`checkip.amazonaws.com`) và UDP giữa 2 instance với nhau.

## Chạy

```bash
git clone --branch claude/magical-volta-6unbmv https://github.com/tamv-ika/glassy.git
cd glassy

# Xem trước các lệnh aws sẽ chạy; danh sách kết thúc bằng các lệnh xoá.
AWS_REGION=ap-southeast-1 bench/aws/s3-ena-probe.sh --dry-run

# Chạy thật (khoảng 25 phút cho 2 loại instance).
AWS_REGION=ap-southeast-1 bench/aws/s3-ena-probe.sh

# Hoặc chỉ một loại:
AWS_REGION=ap-southeast-1 bench/aws/s3-ena-probe.sh --types c7gn.2xlarge
```

Nếu repo là private, CloudShell cần quyền clone (ví dụ chạy `gh auth login` ngay trong CloudShell). Cách khác: nén hai thư mục `bench/aws` và `spikes/cap-probe` (giữ nguyên cấu trúc thư mục, bỏ `target/`), upload qua *Actions → Upload file* rồi giải nén.

CloudShell ngắt session khi không có tương tác trong khoảng 20–30 phút. Hãy giữ tab mở. Nếu session vẫn bị ngắt, script sẽ dọn qua `trap`, còn instance tự terminate sau 120 phút. Muốn an toàn hơn thì chạy từng loại một bằng `--types`.

Gửi lại các file `bench/aws/results/*.json`, bằng cách tải về qua *Actions → Download file* của CloudShell hoặc commit lên branch. Kết quả sẽ được ghi vào mục S3 của `docs/superpowers/spikes/2026-10-21-sp0-findings.md`.

## Đọc kết quả

| Trường | Ý nghĩa |
|---|---|
| `probe.as_booted` | Output của `cap-probe` với cấu hình lúc boot (MTU 9001, dùng hết channel). Nếu XDP native lỗi ở đây, `error` cho biết lý do (MTU, số queue). |
| `probe.prepare_xdp` | Những gì đã đổi để XDP native chạy được: MTU và số channel trước/sau. |
| `probe.after_prepare` | `cap-probe` chạy lại sau khi đã chuẩn bị NIC. |
| `reflect.mode` | `xdpdrv` (native) hoặc `xdpgeneric` (khi native không gắn được). |
| `reflector.rx_pps` | Số gói/giây tới các queue RX của DUT (`queue_*_rx_cnt`). |
| `reflector.tx_pps` | Số gói/giây `xdp_reflect` gửi lại bằng `XDP_TX` (`queue_*_rx_xdp_tx`). |
| `reflector.allowance_exceeded` | Delta của các counter `bw_in/bw_out/pps/conntrack/linklocal_allowance_exceeded`. Khác 0 nghĩa là đã chạm giới hạn của EC2, không phải của XDP. |
| `reflector.deltas` | Mọi counter `ethtool -S` có thay đổi, giữ lại để phân tích thêm. |
| `generator` | Kết quả `pktgen` của từng thread trên GEN. |

Security group dùng rule tracked, nên `conntrack_allowance_exceeded` phản ánh đúng giới hạn mà gateway sẽ gặp khi chạy thật.

## Dọn tay (chỉ khi script bị cắt ngang)

Mọi resource đều có tag `glassy-run=<run id>`; run id được in ở đầu log, dạng `glassy-s3-YYYYmmddHHMMSS`.

```bash
aws ec2 describe-instances --filters Name=tag-key,Values=glassy-run \
  Name=instance-state-name,Values=pending,running,stopping,stopped \
  --query 'Reservations[].Instances[].[InstanceId,Tags[?Key==`glassy-run`]|[0].Value]' --output text
aws ec2 describe-security-groups --filters Name=tag-key,Values=glassy-run --query 'SecurityGroups[].GroupId'
aws ec2 describe-placement-groups --filters Name=tag-key,Values=glassy-run --query 'PlacementGroups[].GroupName'
aws ec2 describe-key-pairs --filters Name=tag-key,Values=glassy-run --query 'KeyPairs[].KeyName'
```

## Test (không cần AWS)

```bash
bench/aws/tests/test_teardown.sh   # in PASS
```

Test thay `aws`, `ssh`, `scp`, `curl` bằng các shim ghi lại lệnh, rồi kiểm rằng mọi resource đều bị xoá: cả khi chạy thành công lẫn khi một bước `run-probe` lỗi giữa chừng.

`remote/run-probe.sh` chạy trên instance; mỗi mode in ra một object JSON (xem phần chú thích ở đầu file).
