"""
가짜 Alert 생성기 (개발용)

앞팀 예측 서버가 완성되기 전까지, 랜덤 Alert JSON을 만들어
FastAPI 서버(/alerts)로 POST 전송한다.

실행 방법:
    python mock/fake_sender.py

종료: Ctrl + C
"""

import random
import time
import uuid
from datetime import datetime
import requests


# ============================================================
# 서버 주소 (개발 중이므로 localhost)
# 나중에 통합 테스트 때는 Tailscale IP로 변경
# ============================================================
SERVER_URL = "http://127.0.0.1:8000/alerts"


# ============================================================
# 랜덤 생성용 데이터 풀
# ============================================================

# 공격 유형별 프리셋 (attack_type + description)
ATTACK_PRESETS = [
    {
        "attack_type": "SSH Brute Force",
        "port": 22,
        "protocol": "TCP",
        "description_tpl": "SSH 포트 22에 {n}초간 {count}회 접속 시도 감지",
    },
    {
        "attack_type": "SYN Flood",
        "port": 80,
        "protocol": "TCP",
        "description_tpl": "TCP SYN 패킷 {count}개 급증 감지 ({n}초 내)",
    },
    {
        "attack_type": "UDP Flood",
        "port": 53,
        "protocol": "UDP",
        "description_tpl": "UDP 트래픽 {count}건 급증 감지 ({n}초 내)",
    },
    {
        "attack_type": "Port Scan",
        "port": None,  # 여러 포트 스캔이라 특정 안 함
        "protocol": "TCP",
        "description_tpl": "{n}초간 {count}개 포트 접근 시도 감지",
    },
    {
        "attack_type": "Web Attack",
        "port": 8080,
        "protocol": "TCP",
        "description_tpl": "비정상적인 HTTP 요청 패턴 감지 ({count}회)",
    },
    {
        "attack_type": "RDP Brute Force",
        "port": 3389,
        "protocol": "TCP",
        "description_tpl": "RDP 포트에 {count}회 인증 시도 감지",
    },
]


# ============================================================
# 헬퍼 함수
# ============================================================

def random_ip():
    """랜덤 사설 IP 생성 (내부 대상 IP용)"""
    return f"192.168.{random.randint(0, 3)}.{random.randint(1, 254)}"


def random_external_ip():
    """랜덤 외부 IP 생성 (공격자 시뮬레이션용)"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_alert():
    """랜덤 Alert JSON 하나 생성"""
    
    # Rule 기반 vs Model 기반 6:4 비율
    detection_type = random.choices(
        ["Rule", "Model"],
        weights=[6, 4]
    )[0]
    
    # 공격 유형 랜덤 선택
    attack = random.choice(ATTACK_PRESETS)
    
    # ID 생성 (rule-xxx 또는 model-xxx)
    short_uuid = uuid.uuid4().hex[:8]
    alert_id = f"{detection_type.lower()}-{short_uuid}"
    
    # detection_type에 따라 confidence 다르게
    if detection_type == "Rule":
        confidence = 1.0
        risk_level = "HIGH"
    else:  # Model
        confidence = round(random.uniform(0.7, 0.99), 2)
        risk_level = "HIGH" if confidence >= 0.85 else "MEDIUM"
    
    # 포트 결정
    src_port = random.randint(30000, 60000)
    dst_port = attack["port"] if attack["port"] else random.randint(1, 65535)
    
    # description 생성 (템플릿 값 채우기)
    description = attack["description_tpl"].format(
        n=random.randint(3, 10),
        count=random.randint(20, 200),
    )
    
    # 최종 JSON
    alert = {
        "alert_id": alert_id,
        "timestamp": datetime.now().isoformat(),
        "src_ip": random_external_ip(),
        "dst_ip": random_ip(),
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": attack["protocol"],
        "attack_type": attack["attack_type"],
        "risk_level": risk_level,
        "confidence": confidence,
        "detection_type": detection_type,
        "description": description,
    }
    
    return alert


def send_alert(alert: dict):
    """Alert을 FastAPI 서버로 POST 전송"""
    try:
        response = requests.post(SERVER_URL, json=alert, timeout=3)
        if response.status_code == 200:
            print(f"✓ [{alert['detection_type']}] {alert['alert_id']} | {alert['attack_type']} | {alert['risk_level']}")
        else:
            print(f"✗ 전송 실패 ({response.status_code}): {response.text}")
    except requests.exceptions.ConnectionError:
        print("✗ 서버 연결 실패 - FastAPI 서버가 실행 중인지 확인하세요.")
    except Exception as e:
        print(f"✗ 에러: {e}")


# ============================================================
# 메인 루프
# ============================================================

def main():
    print("=" * 60)
    print("🚀 가짜 Alert 생성기 시작")
    print(f"   대상 서버: {SERVER_URL}")
    print("   종료: Ctrl + C")
    print("=" * 60)
    
    try:
        while True:
            alert = generate_alert()
            send_alert(alert)
            
            # 1~3초 랜덤 간격 (실전 느낌 나게)
            wait = random.uniform(1, 3)
            time.sleep(wait)
    
    except KeyboardInterrupt:
        print("\n" + "=" * 60)
        print("🛑 가짜 Alert 생성기 종료")
        print("=" * 60)


if __name__ == "__main__":
    main()