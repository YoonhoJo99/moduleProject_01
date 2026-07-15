## IDS 모델 검증을 위한 연구 목적 exploit tool 모음
## 반드시 **허가된 격리 실습 환경** 에서만 사용

공격 스크립트 정리

1. traffic.py
  하위 스크립트 모두 실행
    ftp_patator.py - FTP brute force
    http_get_flood.py - HTTP GET Flood / DoS
    hulk.py - HULK(캐시 우회 Flood) / DoS Hulk
    slowloris.py - Slowloris(저대역폭 slow DoS) - DoS Slowloris
    syn_flood.py - SYN Flood / DDoS
    udp_flood.py - UDP Flood / DDoS

    DoS로 분류한 공격은 src ip를 단일로 설정하였고,
    DDoS로 분류한 공격은 src ip를 랜덤으로 설정하였음.
    랜덤소스 = DDoS가 성립하진 않지만 기법 자체가 DDoS인것은 아닙니다

  nmap tool 기반 SYN, FIN, NULL, XMAS scan
  hydra tool 기반 SSH brute force

2. 사용법
  sudo python3 traffic.py <ip>
    하위 스크립트들은 sudo python3 x.py <ip> <port>
    slowloris, hulk 같은 경우 시간 지정이 필요합니다.
    traffic.py 관리자 권한으로 실행할 때 필요한 모듈을
    확인 후 설치하게 해두었습니다.

3. 요구 사항(타겟)
  HTTP(80) - flood, Hulk, Slowloris
  SSH(22) - SSH Bruteforce
  FTP(21) - FTP Bruteforce
    타겟 머신에서 ss-tlnp | grep :21 // 서비스 확인
    안열려있다면,
    1) sudo apt udpate && sudo apt install -y vsftpd
    2) sudo systemctl start vsftpd
    3) sudo systemctl enable vsftpd
    4) ss -tlnp | grep :21 // 열렸는지 확인