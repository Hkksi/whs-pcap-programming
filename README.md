# WHS PCAP Programming

libpcap을 이용해 Ethernet, IPv4, TCP 헤더와 평문 HTTP 메시지를 출력하는 C++ 프로그램입니다. BPF 필터 `tcp`를 적용하므로 UDP는 캡처 단계에서 제외됩니다.

## 과제 요구사항 대응

| 요구사항 | 구현 |
|---|---|
| C/C++ 기반 PCAP API | C++17 + libpcap |
| Ethernet Header | 출발지/목적지 MAC 주소 출력 |
| IP Header | 출발지/목적지 IPv4 주소 출력 |
| TCP Header | 출발지/목적지 포트 출력 |
| HTTP Message | 평문 HTTP TCP 페이로드 출력 |
| TCP만 분석 | BPF `tcp` 필터 및 IP Protocol 재검증 |
| 헤더 길이 사용 | IPv4 IHL과 TCP Data Offset으로 동적 계산 |

## Ubuntu 24.04 준비

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config libpcap-dev
```

## 빌드

```bash
cmake -S . -B build
cmake --build build
```

## 실행

인터페이스 목록을 확인합니다.

```bash
./build/pcap_sniffer -l
```

실시간으로 캡처합니다. 패킷 캡처 권한이 필요하므로 실습 환경에서는 `sudo`를 사용합니다.

```bash
sudo ./build/pcap_sniffer -i <인터페이스명>
```

저장된 PCAP 파일도 분석할 수 있습니다.

```bash
./build/pcap_sniffer -r sample.pcap
```

평문 HTTP 트래픽 생성 예시:

```bash
curl http://example.com/
```

HTTPS는 암호화되므로 HTTP 본문이 평문으로 출력되지 않습니다.

## 출력 예시

```text
========== TCP Packet ==========
Ethernet Header
  src mac: 00:11:22:33:44:55
  dst mac: aa:bb:cc:dd:ee:ff
IP Header (20 bytes)
  src ip : 192.168.0.10
  dst ip : 93.184.216.34
TCP Header (32 bytes)
  src port: 51234
  dst port: 80
HTTP Message (37 bytes):
GET / HTTP/1.1
Host: example.com
```

위 값은 출력 형식을 보여 주기 위한 예시이며 실제 주소와 메시지는 캡처 환경에 따라 달라집니다.

## 구현 요점

- Ethernet의 EtherType을 확인하고 IPv4만 처리합니다.
- 802.1Q/QinQ VLAN 태그가 있으면 네트워크 헤더 위치를 보정합니다.
- IP의 IHL과 TCP의 Data Offset을 각각 4배하여 실제 헤더 길이를 구합니다.
- IP Total Length와 PCAP의 `caplen`을 모두 검사해 범위를 벗어난 메모리 접근을 막습니다.
- 일반 HTTP 포트 또는 HTTP 시작 문자열이 확인될 때 TCP 페이로드를 출력합니다.
- TCP 세그먼트 재조립은 하지 않으므로 여러 패킷으로 나뉜 HTTP 메시지는 조각별로 표시될 수 있습니다.

## 제출 전 확인

1. Ubuntu 24.04 환경에서 의존성을 설치하고 빌드합니다.
2. `-l`로 인터페이스 이름을 확인합니다.
3. 평문 HTTP 요청을 생성해 MAC, IP, TCP 포트 및 HTTP 메시지 출력을 확인합니다.
4. 같은 패킷을 Wireshark로 열어 출력값과 비교합니다.
5. 본인 GitHub 저장소에 이 폴더의 파일을 업로드합니다. `build/`와 PCAP 파일은 업로드하지 않습니다.
