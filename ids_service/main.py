"""
FastAPI 서버 - Alert 수신 및 저장

엔드포인트:
- POST /alerts : Alert JSON 수신 → SQLite 저장
- GET  /alerts : 저장된 Alert 목록 조회 (테스트용)
- GET  /       : 서버 상태 확인
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from contextlib import asynccontextmanager

from db.database import init_db, insert_alert, get_connection


# ============================================================
# Alert JSON 스키마 정의 (팀 회의 확정본 기준)
# ============================================================
class Alert(BaseModel):
    alert_id: str = Field(..., description="rule-xxx 또는 model-xxx")
    timestamp: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    attack_type: Optional[str] = None
    risk_level: Optional[str] = None       # HIGH / MEDIUM
    confidence: Optional[float] = None
    detection_type: Optional[str] = None   # Rule / Model
    description: Optional[str] = None


# ============================================================
# 서버 시작/종료 시 실행할 것들 (lifespan)
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 서버 시작 시: DB 테이블 없으면 생성
    init_db()
    yield
    # 서버 종료 시: (필요하면 정리 코드 추가)


# ============================================================
# FastAPI 앱 생성
# ============================================================
app = FastAPI(
    title="IDS Alert Service",
    description="침입 탐지 Alert 수신 및 조회 API",
    version="0.1.0",
    lifespan=lifespan,
)


# ============================================================
# 엔드포인트
# ============================================================

@app.get("/")
def root():
    """서버 상태 확인용"""
    return {"status": "ok", "service": "IDS Alert Service"}


@app.post("/alerts")
def receive_alert(alert: Alert):
    """
    Alert 수신 엔드포인트
    앞팀(예측 서버)에서 이곳으로 JSON POST
    """
    try:
        insert_alert(alert.model_dump())
        print(f"[Alert 저장] {alert.alert_id} | {alert.attack_type} | {alert.risk_level}")
        return {"status": "saved", "alert_id": alert.alert_id}
    except Exception as e:
        # 중복 alert_id 등 예외 처리
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/alerts")
def list_alerts(limit: int = 10):
    """
    최근 Alert 목록 조회 (테스트용)
    나중에 챗봇/대시보드도 이 함수 재활용 가능
    """
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]