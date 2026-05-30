# Nội dung trình bày paper HDHUNTER

Paper: **The Silent Danger in HTTP: Identifying HTTP Desync Vulnerabilities with Gray-box Testing**  
Hội nghị: **USENIX Security 2025**  
Tác giả: Keran Mu, Jianjun Chen, Jianwei Zhuge, Qi Li, Haixin Duan, Nick Feamster

File này ghi lại nội dung đã thảo luận trong phiên chat, bằng tiếng Việt, theo các phần cần trình bày:

- Introduction
- 2.1 HTTP, CGI, and Request Smuggling
- 2.2 Fuzzing Techniques
- 3.1 Threat Model
- 4.1 Workflow
- 4.2.1 Structure of Test Case
- 4.2.2 Mutation Strategies
- 4.2.3 Coverage-directed Feedback
- 4.3 Snapshot-based Executor
- 4.4 HTTP Desync Detector
- 5.2 Findings
- 5.3 Attacks

---

## 1. Introduction

Phần Introduction mở đầu bằng bối cảnh: Internet hiện đại không còn đơn giản theo mô hình **end-to-end** ban đầu, nơi client gửi request trực tiếp đến server đích. Trong thực tế, một HTTP request thường phải đi qua nhiều tầng trung gian trước khi đến ứng dụng cuối cùng.

Ví dụ:

```text
Client -> CDN / Proxy -> Firewall / WAF -> Reverse Proxy -> Backend Server
```

Các thành phần trung gian này có thể là:

- proxy,
- firewall,
- CDN,
- reverse proxy,
- cache server,
- application gateway.

Mỗi thành phần có thể dùng một **HTTP implementation** khác nhau. Chúng đều xử lý HTTP, nhưng cách parse và hiểu HTTP/1.1 message không phải lúc nào cũng giống nhau. Chính sự khác biệt này tạo ra nguy cơ **HTTP Desync**.

HTTP Desync xảy ra khi hai thành phần trong cùng một chuỗi xử lý **cùng một HTTP message** theo hai cách khác nhau. Ví dụ:

```text
Proxy hiểu payload là 1 request.
Backend hiểu payload là 2 requests.
```

Khi đó hàng đợi request/response giữa các bên bị lệch nhau. Attacker có thể lợi dụng sự lệch này để chèn, giấu, thao túng hoặc đánh cắp message.

Các hậu quả bảo mật được paper nhắc đến gồm:

- **message smuggling**: giấu request độc hại bên trong request khác,
- **cache poisoning**: đầu độc cache,
- **session hijacking**: chiếm phiên người dùng,
- **account takeover**: chiếm tài khoản,
- **security policy bypass**: vượt qua cơ chế kiểm soát bảo mật.

Thông điệp quan trọng của Introduction là: HTTP Desync không nhất thiết nằm ở một server đơn lẻ. Nó thường xuất hiện khi **nhiều implementation được ghép lại trong cùng một kiến trúc web**.

Paper cũng nhắc đến các công cụ trước đây:

- **Smuggler**: dùng payload định nghĩa sẵn, hiệu quả với mẫu tấn công đã biết nhưng khó tìm biến thể mới.
- **T-Reqs** và **HDiff**: dùng black-box fuzzing để sinh test case dựa trên HTTP grammar hoặc RFC, nhưng thiếu thông tin nội bộ của target.

Các công cụ cũ có hai hạn chế chính:

1. **Black-box testing bị mù trạng thái nội bộ**  
   Công cụ chỉ nhìn input/output bên ngoài, không biết server đã parse đến đâu, dùng `Content-Length` hay `Transfer-Encoding`, consume bao nhiêu byte, nhận ra bao nhiêu message.

2. **Chủ yếu tập trung vào request-side**  
   Nhiều nghiên cứu trước coi HTTP Desync gần như đồng nghĩa với HTTP Request Smuggling. Paper này mở rộng phạm vi sang cả **HTTP response** và **CGI response**.

Để giải quyết, paper đề xuất **HDHUNTER**, một framework phát hiện HTTP Desync bằng:

```text
gray-box testing
+ coverage-directed fuzzing
+ differential testing
```

HDHUNTER dùng coverage từ nhiều implementation để hướng dẫn sinh test case, trích xuất state nội bộ để phát hiện discrepancy, và dùng snapshot để reset trạng thái giữa các lần test.

Kết quả chính:

- test trên **19 HTTP implementations** mã nguồn mở,
- phát hiện **17 HTTP Desync vulnerabilities mới**,
- được gán **9 CVE**,
- nhận **4660 USD bounty** cho lỗ hổng Tomcat.

Đóng góp chính của paper:

1. Đề xuất HDHUNTER, một framework gray-box coverage-directed differential testing để tự động tìm HTTP Desync.
2. Xây dựng prototype và đánh giá trên 19 implementation.
3. Thực hiện nghiên cứu đầu tiên tự động phát hiện Desync ở **HTTP responses** và **CGI responses**.

---

## 2.1 HTTP, CGI, and Request Smuggling

### HTTP/1.1

HTTP là giao thức nền tảng của web, hoạt động theo mô hình **request-response**:

```text
Client gửi request -> Server xử lý -> Server trả response
```

Ví dụ request:

```http
GET /index.html HTTP/1.1
Host: example.com
```

Ví dụ response:

```http
HTTP/1.1 200 OK
Content-Length: 13

Hello, world!
```

Paper tập trung vào **HTTP/1.1**. HTTP/1.1 dùng định dạng text-based, tức là message là văn bản có thể đọc được. Điều này giúp dễ debug và dễ triển khai, nhưng cũng tạo ra nhiều tình huống parsing mơ hồ.

HTTP/1.1 có hai tính năng quan trọng liên quan trực tiếp đến HTTP Desync:

### Persistent Connection

Persistent connection, hay keep-alive, cho phép nhiều request/response dùng chung một TCP connection.

```text
TCP connection:
  Request 1 -> Response 1
  Request 2 -> Response 2
  Request 3 -> Response 3
```

Lợi ích là giảm chi phí tạo kết nối mới. Nhưng đổi lại, parser phải xác định chính xác request này kết thúc ở đâu và request tiếp theo bắt đầu ở đâu.

### HTTP Pipelining

HTTP pipelining cho phép client gửi nhiều request liên tiếp trên cùng một connection mà không cần chờ response trước đó.

```text
Client gửi:
  Request A
  Request B
  Request C

Server phải trả:
  Response A
  Response B
  Response C
```

Điểm quan trọng: response phải được trả **đúng thứ tự**. Nếu thứ tự bị đảo hoặc ranh giới message bị hiểu sai, hàng đợi request/response sẽ bị lệch.

### CGI

CGI là viết tắt của **Common Gateway Interface**. Đây là cơ chế để web server gọi chương trình bên ngoài nhằm sinh nội dung động.

Luồng cơ bản:

```text
Client -> Web Server -> CGI Application -> Web Server -> Client
```

Ví dụ khi user gửi form đăng nhập:

```text
Client gửi POST /login
Web server chuyển dữ liệu cho CGI script
CGI script kiểm tra dữ liệu
CGI script trả kết quả về web server
Web server trả response cho client
```

Các biến thể hoặc công nghệ liên quan đến CGI gồm:

- **WSGI**: thường dùng với Python web applications,
- **FastCGI**: thường dùng với PHP,
- **SCGI**,
- **uWSGI**,
- **Rack**,
- **AJP**: thường liên quan đến Apache/Tomcat.

Điểm quan trọng là trong quá trình chuyển đổi giữa HTTP và CGI/WSGI/FastCGI, mỗi lớp có thể hiểu header, body, hoặc `Content-Length` khác nhau. Điều này mở rộng bề mặt tấn công của HTTP Desync.

### HTTP Request Smuggling

HTTP Request Smuggling là kỹ thuật khai thác sự không nhất quán trong cách các server xác định **ranh giới request**.

Mô hình thường gặp:

```text
Client / Attacker -> Front-end Proxy -> Back-end Server
```

Attacker tạo một HTTP request mơ hồ. Front-end proxy nghĩ đó là một request hợp lệ, nhưng back-end server lại tách nó thành nhiều request.

Ví dụ khái niệm:

```text
Front-end thấy:
  [Request lớn A]

Back-end thấy:
  [Request A]
  [Request độc hại B]
```

Hai header quan trọng nhất trong request smuggling là:

```http
Content-Length
Transfer-Encoding
```

`Content-Length` cho biết body dài bao nhiêu byte:

```http
POST /submit HTTP/1.1
Host: example.com
Content-Length: 5

hello
```

`Transfer-Encoding: chunked` chia body thành các chunk:

```http
POST /submit HTTP/1.1
Host: example.com
Transfer-Encoding: chunked

5
hello
0
```

Theo RFC, một message không nên gửi đồng thời `Content-Length` và `Transfer-Encoding`. Nhưng trong thực tế, các implementation có thể xử lý khác nhau:

```text
Proxy ưu tiên Transfer-Encoding.
Backend ưu tiên Content-Length.
```

Đây là nền tảng của lỗi **TE.CL** hoặc **CL.TE**.

Ví dụ:

```http
POST / HTTP/1.1
Host: victim.com
Content-Length: 4
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: victim.com
```

Một bên có thể nghĩ body đã kết thúc ở chunk `0`, trong khi bên kia đọc theo `Content-Length`. Phần còn lại có thể bị hiểu thành request mới.

Kết luận của mục 2.1: HTTP/1.1, persistent connection, pipelining, CGI conversion, `Content-Length`, và `Transfer-Encoding` tạo ra môi trường thuận lợi cho HTTP Desync.

---

## 2.2 Fuzzing Techniques

Fuzzing là kỹ thuật kiểm thử tự động bằng cách đưa vào chương trình rất nhiều input bất thường, ngẫu nhiên hoặc được biến đổi liên tục để tìm lỗi.

Ví dụ với HTTP server, fuzzer có thể gửi request bình thường:

```http
GET / HTTP/1.1
Host: example.com
```

rồi mutate thành request lạ hơn:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: abc
```

hoặc:

```http
POST / HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 10
```

Paper chia fuzzing thành ba loại:

### Black-box Fuzzing

Black-box fuzzing xem chương trình như hộp đen:

```text
Gửi input vào -> Nhận output ra
```

Fuzzer không biết bên trong chương trình chạy qua nhánh code nào, parser dùng logic gì, trạng thái nội bộ ra sao.

Ưu điểm:

- dễ triển khai,
- không cần source code,
- có thể test dịch vụ đóng.

Nhược điểm:

- test khá mù,
- khó biết input nào mở ra nhánh code mới,
- khó phát hiện bug logic sâu,
- không nhìn được server đã consume bao nhiêu byte hoặc nhận ra bao nhiêu message.

T-Reqs và HDiff thuộc hướng black-box.

### White-box Fuzzing

White-box fuzzing hiểu rất sâu về chương trình, có thể phân tích source code, control flow, symbolic execution. Cách này chính xác nhưng phức tạp, tốn tài nguyên và khó áp dụng cho hệ thống lớn.

### Gray-box Fuzzing

Gray-box fuzzing nằm giữa black-box và white-box. Nó không hiểu toàn bộ chương trình, nhưng dùng một phần thông tin nội bộ, phổ biến nhất là **code coverage**.

Ý tưởng:

```text
Nếu input A làm chương trình chạy vào nhánh code mới,
fuzzer giữ input A lại và tiếp tục mutate từ đó.
```

HDHUNTER thuộc hướng gray-box.

### Coverage-directed Fuzzing

Coverage là mức độ code được thực thi khi chạy một input. Coverage-directed fuzzing dùng thông tin này để quyết định input nào đáng giữ lại.

Quy trình:

```text
1. Chọn input ban đầu.
2. Mutate input.
3. Chạy chương trình.
4. Đo coverage.
5. Nếu có coverage mới, giữ input.
6. Tiếp tục mutate.
```

Với HTTP Desync, coverage rất quan trọng vì nhiều lỗi nằm trong các nhánh ít dùng như:

- trailer section,
- chunked body,
- TE.CL,
- line separator không chuẩn,
- CGI conversion.

### Differential Testing

Differential testing gửi cùng một input vào nhiều implementation rồi so sánh kết quả.

```text
Input X -> Implementation A
Input X -> Implementation B
So sánh hành vi A và B
```

HTTP Desync rất phù hợp với differential testing, vì lỗi không nhất thiết làm server crash. Lỗi nằm ở chỗ hai implementation hiểu cùng một message khác nhau.

Kết luận mục 2.2:

```text
HDHUNTER = Gray-box + Coverage-directed + Differential Testing
```

---

## 3.1 Threat Model

Mục 3.1 định nghĩa mô hình đe dọa của paper.

Cốt lõi của HTTP Desync là:

```text
Cùng một HTTP message
nhưng hai implementation hiểu khác nhau
=> hàng đợi request/response bị lệch
=> attacker có thể chèn, sửa, đánh cắp hoặc làm sai message
```

Trước đây HTTP Desync thường được hiểu gần với HTTP Request Smuggling. Paper này mở rộng phạm vi rộng hơn, bao gồm cả request-side và response-side.

Paper chia sai khác thành ba loại chính:

1. **Inconsistent number of messages**
2. **Inconsistent content of messages**
3. **Inconsistent order of messages**

Ba loại này có thể xảy ra ở cả request và response, tạo thành sáu dạng HTTP Desync.

### Request-side: Inconsistent Number of Messages

Đây là dạng truyền thống nhất.

```text
Proxy hiểu payload là 1 request.
Backend hiểu payload là 2 requests.
```

Request thứ hai có thể là request độc hại được attacker giấu vào request đầu.

Nguyên nhân thường nằm ở các trường xác định ranh giới body:

- `Content-Length`,
- `Transfer-Encoding`,
- chunk size,
- trailer section,
- connection state.

### Request-side: Inconsistent Content of Messages

Ở dạng này, hai implementation có thể đồng ý rằng payload là một request, nhưng hiểu **nội dung request** khác nhau.

Ví dụ:

```text
Implementation A:
  Body = "abc"

Implementation B:
  Body = "abcdef"
```

Hoặc:

```text
Gateway truyền CONTENT_LENGTH = 0
nhưng application vẫn parse được body
```

Dạng này thường xuất hiện trong chuyển đổi HTTP sang CGI/WSGI/FastCGI.

### Request-side: Inconsistent Order of Messages

Với pipelining, server phải trả response theo đúng thứ tự request. Nếu response bị đảo thứ tự, hàng đợi bị lệch.

```text
Gửi:
  Request A
  Request B

Đúng:
  Response A
  Response B

Sai:
  Response B
  Response A
```

### Response-side Desync

Điểm mới quan trọng của paper là mở rộng sang response-side.

Trong hạ tầng hiện đại, một proxy/CDN/API gateway có thể phục vụ nhiều upstream:

```text
/api/user    -> upstream A
/api/payment -> upstream B
/evil        -> upstream attacker kiểm soát
```

Nếu attacker kiểm soát một upstream và response parser của proxy/client có discrepancy, attacker có thể chèn response mơ hồ vào hàng đợi response.

Hậu quả:

- **Response Stealing**: lấy nhầm response của người khác,
- **Response Forgery**: chèn response giả,
- response queue poisoning.

Tóm lại, threat model của paper mở rộng HTTP Desync từ request smuggling truyền thống thành taxonomy rộng hơn:

```text
Request-side: number, content, order
Response-side: number, content, order
```

---

## 4.1 Workflow

Mục 4.1 trình bày luồng hoạt động tổng thể của HDHUNTER.

HDHUNTER là:

```text
gray-box
coverage-directed
differential fuzzing
```

Nó dựa trên mô hình AFL-like fuzzing framework, dùng ý tưởng gần với genetic algorithm: có corpus ban đầu, chọn input, mutate, chạy, đo coverage/state, rồi quyết định giữ input nào.

Workflow gồm 7 bước:

### Bước 1: Seed Collection

Tác giả trích xuất HTTP messages từ network traffic thật, đưa vào corpus làm seed ban đầu.

Seed thật giúp fuzzer bắt đầu từ input hợp lệ, thay vì random bytes dễ bị server reject ngay.

### Bước 2: Chọn Test Case từ Corpus

Fuzzer chọn một test case trong corpus. Corpus chứa các input có giá trị, ví dụ input tạo coverage mới hoặc giúp mở nhánh parser mới.

### Bước 3: Mutate Test Case

HDHUNTER dùng mutator để biến đổi test case ở nhiều mức:

- sequence,
- message,
- byte.

Mục tiêu là tạo input vừa giống HTTP thật, vừa đủ bất thường để làm lộ discrepancy.

### Bước 4: Executor chạy input trên hai implementations

Cùng một input được chạy trên hai implementation.

```text
Input X -> Implementation A
Input X -> Implementation B
```

Trong lúc chạy, HDHUNTER thu:

- coverage,
- internal states.

### Bước 5: Detector tìm discrepancy

Detector so sánh state tuple của hai implementation. Nếu khác biệt, nó tạo report.

### Bước 6: Feedback

Feedback quyết định input có đáng đưa vào corpus không. Nếu input mở edge coverage mới, nó có giá trị.

Chi tiết thú vị: nếu input vừa tạo new edge vừa gây discrepancy, HDHUNTER không nhất thiết thêm nó vào corpus, vì mutate từ input đó dễ lặp lại discrepancy cũ và làm giảm hiệu quả khám phá.

### Bước 7: Manual Analysis

Các discrepancy được phân tích thủ công để xác định có thật sự là vulnerability khai thác được hay không.

Tóm lại:

```text
Seed -> Corpus -> Mutator -> Executor -> Detector -> Feedback -> Corpus
                                   |
                                   v
                            Manual analysis
```

---

## 4.2.1 Structure of Test Case

HTTP/1.1 là giao thức text-based. Nếu fuzzer chỉ mutate byte ngẫu nhiên, nó dễ tạo input vô nghĩa và bị server reject ngay.

Do đó HDHUNTER không xem test case là chuỗi byte thô, mà xây dựng test case có cấu trúc HTTP.

Một HTTP message gồm ba phần:

```text
Start line
Field lines / headers
Message body
```

Ví dụ request:

```http
POST /login HTTP/1.1
Host: example.com
Content-Length: 11

hello=world
```

Trong đó:

```text
Start line:  POST /login HTTP/1.1
Headers:     Host, Content-Length
Body:        hello=world
```

HTTP response cũng có cấu trúc tương tự, khác chủ yếu ở start line:

```http
HTTP/1.1 200 OK
Content-Length: 5

hello
```

CGI response hơi khác: status code có thể nằm trong header `Status`, không phải start line.

Ví dụ:

```http
Status: 200 OK
Content-Type: text/html

hello
```

HDHUNTER thiết kế một cấu trúc chung dùng được cho:

- HTTP request,
- HTTP response,
- CGI response.

### Test Case là mảng HTTP messages

Vì HTTP/1.1 hỗ trợ persistent connection và pipelining, một test case có thể chứa nhiều HTTP messages:

```text
Test case:
  Message 1
  Message 2
  Message 3
```

Điều này quan trọng vì Desync thường chỉ xuất hiện khi nhiều message đi chung một connection.

### Dynamic Tree Structure

HDHUNTER lưu message bằng cấu trúc cây dựa trên ABNF grammar từ RFC:

```text
HTTP-message
  start-line
  field-lines
    header-name
    header-value
  message-body
```

Mỗi field được gắn datatype:

- string,
- number,
- symbol.

Datatype giúp mutator chọn chiến lược phù hợp. Ví dụ:

- thay number bằng `0x8`, `+8`, `1_0`,
- swap hai value cùng kiểu,
- thay header value bằng token đặc biệt.

Tuy nhiên label không giới hạn tuyệt đối kiểu dữ liệu. Fuzzer vẫn có thể tạo giá trị không chuẩn, vì chính các giá trị không chuẩn thường gây discrepancy.

Kết luận: Cấu trúc test case của HDHUNTER giúp fuzzer tạo input có ý nghĩa hơn byte-level random fuzzing.

---

## 4.2.2 Mutation Strategies

HDHUNTER mutate test case ở ba tầng:

```text
1. Sequence-level
2. Message-level
3. Byte-level
```

Một test case có thể trải qua nhiều mutation trong một vòng.

### Sequence-level Mutation

Tầng này xử lý ở mức chuỗi nhiều HTTP messages.

Do HTTP/1.1 hỗ trợ persistent connection và pipelining, lỗi Desync thường liên quan đến nhiều message nối tiếp nhau.

Các chiến lược:

- chọn một message từ corpus và thêm vào sequence,
- xóa một message khỏi sequence.

Ví dụ:

```text
[Request A]
```

sau mutation:

```text
[Request A][Request B]
```

Mục tiêu là tìm lỗi liên quan đến:

- message queue,
- pipelining,
- persistent connection,
- order of messages.

### Message-level Mutation

Tầng này xử lý bên trong một HTTP message.

Các chiến lược:

- duplicate một field line,
- delete một field line,
- insert field line từ corpus,
- swap hai value cùng datatype,
- replace value bằng token đặc biệt,
- modify trailer section.

Ví dụ duplicate header:

```http
Content-Length: 5
Content-Length: 10
```

Một implementation có thể lấy giá trị đầu, implementation khác lấy giá trị sau, hoặc reject.

Ví dụ TE.CL:

```http
Transfer-Encoding: chunked
Content-Length: 20
```

Đây là tình huống nhạy cảm vì cả hai header cùng ảnh hưởng đến boundary của body.

### Byte-level Mutation

Tầng này thêm tính ngẫu nhiên ở mức byte:

- insert byte,
- remove byte,
- duplicate byte,
- splice byte từ corpus.

Tầng này giúp tìm các lỗi do parser quá dễ dãi với input sai chuẩn, ví dụ:

- LF thay vì CRLF,
- ký tự dư sau chunk size,
- whitespace lạ,
- header format không chuẩn.

Ba tầng mutation bổ sung cho nhau:

```text
Sequence-level: lỗi queue/pipelining.
Message-level: lỗi header/body/chunk/trailer.
Byte-level: lỗi robust parsing và ký tự sai chuẩn.
```

---

## 4.2.3 Coverage-directed Feedback

Coverage-directed feedback quyết định input nào đáng giữ lại trong corpus.

Trong AFL, fuzzer dùng edge hit count map để biết input có kích hoạt nhánh code mới không. Nếu có, input được giữ lại.

HDHUNTER áp dụng ý tưởng này nhưng có điểm khác: nó test **hai implementation cùng lúc**.

Thay vì một coverage map:

```text
Coverage map của Implementation A
```

HDHUNTER có:

```text
Coverage map A + Coverage map B
```

Hai map được nối lại thành một double-sized edge map:

```text
[Impl A edge map] + [Impl B edge map] -> Combined edge map
```

Nhờ vậy, nếu input không tạo edge mới ở A nhưng tạo edge mới ở B, nó vẫn có giá trị.

Điểm đặc biệt: nếu seed vừa trigger new edges vừa trigger discrepancy, HDHUNTER không thêm seed đó vào corpus trong quá trình fuzzing.

Lý do:

```text
Mutate từ seed đã gây discrepancy dễ tạo lại cùng discrepancy cũ,
làm fuzzer bị kẹt và giảm khả năng tìm lỗi mới.
```

Kết luận: combined coverage là điểm giúp HDHUNTER đưa coverage-guided fuzzing vào differential testing giữa nhiều implementation.

---

## 4.3 Snapshot-based Executor

Mục 4.3 nói về executor, tức thành phần chạy test case trên các implementation.

HTTP Desync liên quan rất nhiều đến state:

- TCP connection state,
- HTTP message queue,
- internal buffer,
- persistent connection,
- pipelining state.

Nếu sau mỗi test không reset sạch, test sau có thể bị ảnh hưởng bởi test trước.

Ví dụ:

```text
Test 1 để lại nửa request trong buffer.
Test 2 chạy sau đó bị ghép với phần dư này.
Detector tưởng Test 2 gây Desync.
```

Điều này tạo false positive hoặc false negative.

### Vì sao cần snapshot

Cách đơn giản là restart server sau mỗi input, nhưng quá chậm, đặc biệt với server lớn như Tomcat.

HDHUNTER dùng snapshot:

```text
1. Khởi động target.
2. Đợi target sẵn sàng.
3. Chụp snapshot.
4. Chạy test case.
5. Restore snapshot.
6. Chạy test case tiếp theo.
```

Snapshot giúp mỗi input bắt đầu từ trạng thái sạch hơn mà không phải restart toàn bộ server.

### Coverage Collection

HDHUNTER hỗ trợ cả implementation viết bằng compiled languages và interpreted languages.

Với C/C++:

- dùng SanitizerCoverage của Clang.

Với interpreted languages:

- áp dụng hướng của Witcher, chỉnh bytecode interpreter để cập nhật coverage theo line number và opcode.

Coverage được thu từ hai process trong hai QEMU guest, thông qua shared memory và guest memory access.

### 4.3.1 Snapshot-based State Recovery

HTTP chạy trên TCP/IP, nên trạng thái mạng còn lại sau mỗi test ảnh hưởng đến parsing. Mỗi implementation cũng có buffer riêng.

HDHUNTER tái sử dụng cơ chế reload snapshot nhanh của Nyx, nhưng tự triển khai AFL-like coverage collection phù hợp với userspace HTTP servers.

Harness dùng Linux socket API gốc để giao tiếp với target. Điều này thực tế hơn so với custom network stack.

Harness kiểm tra target sẵn sàng bằng benign probing input. Khi input lành tính được accept, hệ thống coi target đã ready và chụp snapshot.

### 4.3.2 Support for HTTP Requests, Responses, and CGI Responses

HDHUNTER có hai mode:

### Mode 1: HTTP Request

Harness lấy test case, format thành HTTP request, gửi trực tiếp vào implementation.

```text
Executor -> Harness -> Implementation
```

Mode này dùng để test request-side desync.

### Mode 2: HTTP/CGI Response

HTTP server bình thường không nhận response từ client. Vì vậy muốn test response parser, harness phải giả lập upstream/backend.

Luồng:

```text
Harness(client giả) -> Target proxy/server -> Harness(upstream giả)
Harness(upstream giả) -> fuzzed response -> Target proxy/server
Target proxy/server -> response -> Harness(client giả)
```

Nói cách khác:

```text
Harness đứng ở hai đầu target:
Harness(client giả) -> Proxy/Target -> Harness(backend giả)
```

Trong mode này, backend thật không phải trọng tâm. Backend được harness thay thế để trả response fuzzed. Mục tiêu là xem proxy/target parse response từ upstream như thế nào.

Mode này cũng dùng cho CGI response, vì CGI response có thể được gateway chuyển thành HTTP response thật. Nếu gateway xử lý `Content-Length`, `Transfer-Encoding`, hoặc body không đúng, có thể tạo response desync.

Kết luận mục 4.3: Snapshot-based executor giúp fuzzing nhanh, ổn định, và hỗ trợ cả request-side lẫn response/CGI response-side.

---

## 4.4 HTTP Desync Detector

Mục 4.4 trình bày bộ phát hiện HTTP Desync của HDHUNTER.

Trong fuzzing lỗi memory, nếu chương trình crash thì dễ biết có lỗi. Nhưng HTTP Desync thường không gây crash. Server vẫn chạy bình thường, chỉ là nó hiểu message khác server khác.

Vì vậy cần detector riêng.

Detector so sánh hành vi của hai implementation với cùng một input:

```text
Input X -> Implementation A -> State Tuple A
Input X -> Implementation B -> State Tuple B
Compare A and B
```

### Vì sao không chỉ nhìn output bên ngoài

Nhìn forwarded request/response bên ngoài không đủ chính xác, vì proxy/server có thể sanitize hoặc post-process message.

Ví dụ NGINX có thể nhận request chunked nhưng khi forward xuống backend lại chuyển thành raw body. Nhìn message forwarded không biết chắc NGINX đã parse bằng chunked hay raw.

Do đó HDHUNTER trích xuất internal state từ bên trong implementation.

### State Tuple

HDHUNTER thu thập bảy trường:

```text
(Count, Consumed, Body, Encoding, CL, Order, Status)
```

Ý nghĩa:

- **Count**: số request/response implementation nhận ra.
- **Consumed**: số byte implementation consume trong quá trình parsing.
- **Body**: nội dung body đã parse, hoặc độ dài body nếu khó lấy content.
- **Encoding**: parser dùng raw hay chunked.
- **CL**: giá trị `Content-Length` parser hiểu.
- **Order**: thứ tự message/response.
- **Status**: HTTP status code.

Năm trường đầu được lấy bằng code insertion vào các hàm xử lý HTTP của implementation:

```text
Count, Consumed, Body, Encoding, CL
```

Hai trường còn lại lấy từ bên ngoài:

- `Order`: dùng header `X-Desync-Id` với UUID để theo dõi thứ tự response.
- `Status`: đọc status line từ response.

### Detection Rule

Detector so sánh State Tuple của hai implementation.

Với:

```text
Count
Body
Order
```

nếu khác nhau thì báo discrepancy.

Với:

```text
Encoding
CL
Consumed
```

detector xét `Status` trước. Nếu cả hai implementation đều trả lỗi 4xx/5xx, thì coi như cả hai cùng reject message. Khi đó so sánh encoding, CL, consumed không còn nhiều ý nghĩa.

Ví dụ:

```text
Implementation A: 400 Bad Request
Implementation B: 400 Bad Request
```

Dù nội bộ có khác nhau, cả hai đều reject, nên không nhất thiết là Desync khai thác được.

Kết luận mục 4.4: Detector biến HTTP Desync từ hiện tượng khó quan sát thành các state cụ thể có thể so sánh.

---

## 5.2 Findings

Phần 5.2 trình bày các nhóm discrepancy chính mà HDHUNTER tìm được.

Tổng cộng, HDHUNTER phát hiện **17 HTTP Desync vulnerabilities mới**, ảnh hưởng đến nhiều implementation nổi tiếng như Apache, Tomcat, Squid, Twisted, gevent, Eventlet. Có **9 CVE** được gán.

Paper nêu năm nhóm discrepancy chính.

### 5.2.1 Non-standard Number Parsing

Các trường số trong HTTP có vai trò xác định ranh giới body, đặc biệt là:

- `Content-Length`,
- chunk size trong chunked encoding.

Theo RFC:

- `Content-Length` dùng chữ số thập phân,
- chunk size dùng số hệ 16.

Nhưng HDHUNTER phát hiện nhiều implementation chấp nhận định dạng số không chuẩn:

- `0x` prefix,
- `+` prefix,
- dấu `_` ở giữa số,
- suffix lạ phía sau số.

Ví dụ:

```http
Content-Length: 0x8
Content-Length: +8
Transfer-Encoding: chunked

1_0
abcdefghijabcdef
0
```

Mỗi implementation có thể hiểu khác nhau:

```text
Implementation A hiểu 0x8 là 8.
Implementation B coi 0x8 là không hợp lệ.
Implementation C chỉ đọc số 0.
```

Ví dụ paper nêu Squid và H2O xử lý chunk size `0x8` khác nhau. Squid xử lý như chunk bình thường, trong khi H2O có thể coi là last chunk. Điều này làm lệch boundary của message.

### 5.2.2 Inconsistent Trailer Section Acceptance

Trailer section là metadata xuất hiện sau body trong chunked encoding.

Ví dụ:

```http
Transfer-Encoding: chunked

5
hello
0
Expires: tomorrow

```

Trailer là một phần của RFC nhưng ít dùng, nên các implementation hỗ trợ rất khác nhau.

Paper chia thành hai giai đoạn:

1. **Parsing stage**: server có chấp nhận trailer không, có validate format không.
2. **Forwarding stage**: proxy có sanitize hoặc forward raw trailer không.

Một số implementation như Apache HTTP Server và HAProxy validate trailer chặt hơn. NGINX có thể chấp nhận trailer malformed. Một số implementation khác không hỗ trợ trailer đúng cách.

Các implementation như gevent, Eventlet, Puma có thể hiểu trailer section thành message/request khác, dẫn đến một request bị tách thành hai.

Tomcat có hỗ trợ trailer nhưng vẫn có vấn đề khi dòng trailer không có dấu `:`.

### 5.2.3 Non-standard Line Separator

HTTP chuẩn dùng `CRLF`, tức `\r\n`, để kết thúc dòng.

Một số implementation chấp nhận chỉ `LF`, tức `\n`.

Nếu một implementation chỉ công nhận CRLF, còn implementation khác chấp nhận cả LF, cùng một payload có thể bị chia dòng khác nhau.

Điều này ảnh hưởng đến:

- start line,
- header line,
- chunk size line,
- trailer section,
- ranh giới giữa body và request tiếp theo.

Paper nói đã verify payload dạng này trên NGINX và Gunicorn.

### 5.2.4 Different Request TE.CL Handling Strategies

TE.CL là tình huống request có cả:

```http
Transfer-Encoding: chunked
Content-Length: ...
```

Nhiều implementation hiện đại đã có biện pháp giảm rủi ro, nhưng cách xử lý vẫn khác nhau:

- có bên reject request,
- có bên accept request,
- có bên đóng persistent connection,
- có bên giữ connection.

uWSGI mặc định không hỗ trợ chunked encoding, nên có thể đọc body theo `Content-Length`.

Eventlet và Gunicorn hỗ trợ WSGI, có thể nhận chunked body nhưng vẫn truyền `Content-Length` xuống app qua biến môi trường `CONTENT_LENGTH`. Điều này có thể làm application hiểu sai body.

### 5.2.5 Different Response TE.CL Handling Strategies

Đây là điểm mới quan trọng: response cũng có thể có TE.CL.

HTTP request và response khác nhau chủ yếu ở start line; phần header/body phía sau tương tự. Nếu TE.CL gây mơ hồ ở request, nó cũng có thể gây mơ hồ ở response.

Paper phát hiện:

- Varnish trả lỗi khi nhận response có cả TE và CL.
- H2O và Twisted có hành vi chấp nhận CL trong response khác với cách xử lý request.
- Twisted có thể forward cả TE và CL xuống downstream client.

Với CGI response, các proxy thể hiện nhiều hành vi khác nhau:

- Lighttpd và HAProxy accept TE/chunked body.
- NGINX và H2O accept CL.
- Apache có thể forward cả TE, CL và body xuống downstream mà không sanitize đầy đủ.

Các module Apache liên quan gồm FastCGI, SCGI, uWSGI, AJP.

### 5.2.6 Other Notable Discrepancies

Paper phát hiện Twisted có thể xử lý pipelined requests đồng thời mà không đảm bảo response trả đúng thứ tự.

Nếu request thứ hai xử lý nhanh hơn request thứ nhất, Twisted có thể trả response thứ hai trước.

Điều này gây:

```text
Inconsistent order of responses
```

Đây là nền cho Response Stealing.

Tổng kết 5.2:

```text
Non-standard number parsing -> lệch CL/chunk size.
Trailer section -> lệch phần kết thúc body.
Line separator -> lệch ranh giới dòng.
Request TE.CL -> lệch request boundary/content.
Response TE.CL -> lệch response boundary.
Order discrepancy -> lệch thứ tự response.
```

---

## 5.3 Attacks

Phần 5.3 chứng minh các discrepancy không chỉ là khác biệt kỹ thuật, mà có thể dẫn đến tấn công thật.

Paper trình bày bốn dạng tấn công:

1. Request Smuggling
2. Request Confusing
3. Response Stealing
4. Response Forgery

### 5.3.1 Request Smuggling

Request Smuggling là dạng quen thuộc nhất.

Ý tưởng:

```text
Proxy thấy payload là 1 request.
Backend thấy payload là 2 requests.
```

Attacker giấu request độc hại bên trong request đầu tiên.

Ví dụ proxy chặn `/admin`, nhưng attacker gửi payload sao cho:

```text
Proxy thấy request tới /path1, cho phép.
Backend parse thêm request /admin hoặc /path2.
```

Paper nêu ví dụ với Apache Traffic Server và gevent. ATS forward raw request có trailer section, còn gevent hiểu trailer khác, dẫn đến request bị smuggle.

Root cause:

```text
Inconsistent number of requests
```

### 5.3.2 Request Confusing

Request Confusing không nhất thiết tạo thêm request mới. Thay vào đó, các lớp khác nhau hiểu **nội dung request** khác nhau.

Ví dụ với Gunicorn và Flask:

```text
Gunicorn xử lý body theo chunked.
Nhưng vẫn truyền Content-Length xuống Flask qua CONTENT_LENGTH.
Flask có thể thấy request.content_length = 0,
nhưng request.form vẫn parse được dữ liệu.
```

Nếu developer viết logic dựa vào `content_length`, attacker có thể bypass điều kiện.

Root cause:

```text
Inconsistent content of requests
```

### 5.3.3 Response Stealing

Response Stealing là tấn công phía response.

Trong HTTP pipelining:

```text
Request A
Request B
```

Server phải trả:

```text
Response A
Response B
```

Nếu server trả:

```text
Response B
Response A
```

proxy/client có thể gán nhầm response.

Paper nêu Twisted có thể xử lý pipelined requests đồng thời, làm request sau trả response trước request trước. Attacker có thể lợi dụng để lấy response đáng lẽ thuộc về victim.

Root cause:

```text
Inconsistent order of responses
```

### 5.3.4 Response Forgery

Response Forgery là tấn công trong đó attacker chèn hoặc giả mạo response để victim nhận response sai.

Paper liên hệ với lỗi xử lý CGI response TE.CL trong Apache.

Kịch bản:

```text
Attacker-controlled CGI application -> Apache proxy/gateway -> Downstream client
```

CGI app trả response mơ hồ, ví dụ có `Content-Length` nhỏ và body chứa response giả. Apache có thể forward cả TE, CL và toàn bộ body xuống downstream.

Downstream/client có thể hiểu:

```text
Response đầu kết thúc sớm.
Phần còn lại là response thứ hai.
```

Khi đó attacker chèn được response giả vào response queue.

Root cause:

```text
Inconsistent number of responses
```

### Tổng kết 5.3

Bốn attack map trực tiếp với threat model:

```text
Request Smuggling:
  Lệch số lượng request.

Request Confusing:
  Lệch nội dung request.

Response Stealing:
  Lệch thứ tự response.

Response Forgery:
  Lệch số lượng response.
```

Thông điệp chính: HTTP Desync không chỉ là request smuggling cổ điển. Nó có thể xảy ra ở request content, response boundary, response order, và CGI conversion.

---

## Ghi chú cho phần demo project

Trong phần thảo luận về project, ta đã thống nhất nên trình bày code/testbed là:

```text
Mini testbed inspired by HDHUNTER
```

Không nên nói là đã implement đầy đủ HDHUNTER, vì các phần sau rất khó thực hiện trong phạm vi môn học:

- không có source-code instrumentation để lấy internal State Tuple,
- không có coverage feedback thật,
- không dùng QEMU/Nyx snapshot,
- không test 19 implementations theo pair như paper,
- không kết luận exploitability/CVE.

Mục tiêu project nên được nói rõ:

```text
Gửi cùng raw HTTP payload qua reverse proxy và trực tiếp đến backend,
sau đó so sánh trạng thái quan sát được để tìm parsing discrepancy candidate.
```

Các discrepancy tìm được trong project nên gọi là:

```text
candidate discrepancy
```

và cần replay/PoC thủ công trước khi gọi là vulnerability.
