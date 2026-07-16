# 네트워크보안 수업용 트래픽공격 캡처 파일

이번 프로젝트 마치고 다음 수업이 네트워크 보안으로 알고 있습니다.

혹시라도 수업 중에 이번 공격 실습 중 나왔던 공격 유형이 나온다면 공부에 도움 되시라고 캡처파일 올려놓습니다.

## 읽는 방법

- **리눅스**: `tcpdump -r 파일명`
- **윈도우**: `tshark -r 파일명`
- **공통(GUI)**: Wireshark로 열기

※ tshark는 Wireshark 설치 시 함께 설치됩니다.

## 파일 목록

각 파일은 해당 공격의 실제 트래픽입니다.

- `syn_flood.pcap` — SYN Flood
- `udp_flood.pcap` — UDP Flood
- `http_get_flood.pcap` — HTTP GET Flood
- `hulk.pcap` — HULK (캐시 우회 Flood)
- `slowloris.pcap` — Slowloris (저대역폭 slow DoS)
- `rudy.pcap` — RUDY (slow POST)
- `portscan.pcap` — 포트 스캔 (SYN/FIN/NULL/XMAS)
- `ssh_brute.pcap` — SSH Brute Force
- `ftp_brute.pcap` — FTP Brute Force (평문이라 USER/PASS 확인 가능)
- `dns_flood.pcap` / `ntp_flood.pcap` / `snmp_flood.pcap` / `ssdp_flood.pcap` — UDP 기반 Flood