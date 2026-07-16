# IDS 모델 검증을 위한 연구 목적 Exploit Tool 모음

머신러닝 기반 침입 탐지(IDS) 모델의 학습 및 검증에 사용할 공격 트래픽을 생성하는 스크립트 모음입니다.

> ⚠️ **사용 제한**
> 본 스크립트는 IDS 모델 학습·검증을 위한 **교육/연구 목적**으로만 제작되었습니다.

---

## 1. 공격 스크립트 구성

### traffic.py — 통합 실행

`traffic.py` 실행 시 아래 하위 스크립트를 순차적으로 모두 실행합니다.

| 스크립트 | 공격 | CICIDS2017 분류 |
|----------|------|-----------------|
| `syn_flood.py` | SYN Flood | DDoS |
| `udp_flood.py` | UDP Flood | DDoS |
| `http_get_flood.py` | HTTP GET Flood | DoS |
| `hulk.py` | HULK (캐시 우회 Flood) | DoS Hulk |
| `slowloris.py` | Slowloris (저대역폭 slow DoS) | DoS Slowloris |
| `ftp_patator.py` | FTP Brute Force | FTP-Patator |

`traffic.py` 내부에서 추가로 실행:
- **nmap** 기반 포트 스캔 (SYN / FIN / NULL / XMAS) → PortScan
- **hydra** 기반 SSH Brute Force → SSH-Patator

> **DoS / DDoS 분류 기준**
> DoS로 분류한 공격은 src IP를 단일로, DDoS로 분류한 공격은 src IP를 랜덤으로 설정하였습니다.
> 랜덤 소스 = DDoS가 성립하는 것은 아니며, 기법 자체가 DDoS인 것도 아닙니다.

---

## 2. 공격별 상세 특성

**1. SYN Flood**
랜덤 소스 IP로 설정하였고, SYN 패킷만 대량 전송하도록 코딩
*(CICIDS에서는 DDoS로 분류)*

**2. UDP Flood**
랜덤 소스 IP로 설정하였고, 의미 없는 UDP 패킷을 대량 전송하여 대역폭 소진토록 설정
*(destPort를 53으로 설정하였으나 DNS Flood와는 형태 상이함)*

※ SYN Flood, UDP Flood는 hping3 툴로 단순화 가능

**3. HTTP GET Flood**
정상적인 형태의 GET 요청을 대량으로 반복 전송하여 웹서버 자원 소진토록 설정
*(CICIDS에서는 DoS로 분류)*

**4. Hulk**
매 요청마다 랜덤 파라미터를 붙여 캐시를 우회하며, 고대역폭으로 GET 요청 대량 전송 설정
*(CICIDS에서는 DoS Hulk로 분류)*

**5. Slowloris**
미완성 HTTP 헤더를 천천히 전송하여 연결을 오래 유지시키는 저대역폭 방식으로 설정
*(CICIDS에서는 DoS Slowloris로 분류)*

**6. PortScan (nmap)**
SYN / FIN / NULL / XMAS 등 스캔 방식 다양화
*(CICIDS에서는 PortScan으로 분류)*

**7. SSH Brute Force (hydra)**
test 유저와 간단한 password list로 SSH 로그인 시도 설정
*(CICIDS에서는 SSH-Patator로 분류)*

**8. FTP Brute Force**
간단한 user list, password list로 FTP 로그인 시도 설정
*(CICIDS에서는 FTP-Patator로 분류)*

---

## 3. 사용법

```bash
sudo python3 traffic.py 
```

- 하위 스크립트 개별 실행: `sudo python3 <script>.py <ip> <port>`
- `slowloris`, `hulk`는 실행 시 시간 지정이 필요합니다.
- traffic.py에 slowloris와 hulk 시간 지정은 기본으로 해두었습니다.
- 개별 실행 시 시간 지정이 필요합니다
- `traffic.py`를 관리자 권한으로 실행하면 필요한 모듈을 자동으로 확인·설치합니다.
- sudo 명령어를 사용하여 실행하지 않으면 필요한 모듈을 설치하지 못합니다.

---

## 4. 요구 사항 (타겟 머신)

아래 서비스가 열려 있어야 해당 공격이 정상적으로 동작합니다.

| 포트 | 서비스 | 관련 공격 |
|------|--------|-----------|
| 80 | HTTP | Flood, Hulk, Slowloris |
| 22 | SSH | SSH Brute Force |
| 21 | FTP | FTP Brute Force |

### FTP(21) 서비스 확인 및 설정

```bash
# 열려 있는지 확인
ss -tlnp | grep :21

# 안 열려 있다면 설치
sudo apt update && sudo apt install -y vsftpd
sudo systemctl start vsftpd
sudo systemctl enable vsftpd

# 다시 확인
ss -tlnp | grep :21
```