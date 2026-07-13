"""
SQLite 데이터베이스 연결 및 쿼리 모듈

- alerts.db 파일을 자동 생성
- alerts 테이블 자동 생성
- Alert 저장 함수 제공
"""

import sqlite3
from pathlib import Path

# DB 파일 경로 (db 폴더 안에 alerts.db 생성)
DB_PATH = Path(__file__).parent / "alerts.db"


def get_connection():
    """SQLite 연결 객체 반환"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # 결과를 dict처럼 사용 가능
    return conn


def init_db():
    """
    DB 초기화: alerts 테이블 생성 (없을 경우에만)
    서버 시작 시 1회 호출
    """
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id       TEXT PRIMARY KEY,
            timestamp      TEXT NOT NULL,
            src_ip         TEXT,
            dst_ip         TEXT,
            src_port       INTEGER,
            dst_port       INTEGER,
            protocol       TEXT,
            attack_type    TEXT,
            risk_level     TEXT,
            confidence     REAL,
            detection_type TEXT,
            description    TEXT
        )
    """)
    
    # 자주 조회하는 컬럼에 인덱스 추가 (조회 속도 향상)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_attack_type ON alerts(attack_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_level ON alerts(risk_level)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detection_type ON alerts(detection_type)")
    
    conn.commit()
    conn.close()
    print(f"[DB] 초기화 완료: {DB_PATH}")


def insert_alert(alert: dict):
    """
    Alert 하나를 DB에 저장
    
    Args:
        alert: JSON에서 파싱한 dict
    """
    conn = get_connection()
    conn.execute("""
        INSERT INTO alerts (
            alert_id, timestamp, src_ip, dst_ip,
            src_port, dst_port, protocol, attack_type,
            risk_level, confidence, detection_type, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["alert_id"],
        alert["timestamp"],
        alert.get("src_ip"),
        alert.get("dst_ip"),
        alert.get("src_port"),
        alert.get("dst_port"),
        alert.get("protocol"),
        alert.get("attack_type"),
        alert.get("risk_level"),
        alert.get("confidence"),
        alert.get("detection_type"),
        alert.get("description"),
    ))
    conn.commit()
    conn.close()