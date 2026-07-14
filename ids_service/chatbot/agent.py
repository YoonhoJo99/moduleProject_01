"""
IDS 챗봇 로직 (재사용 가능한 함수 모듈)

Streamlit UI와 분리된 순수 로직만 담고 있음.
대시보드(dashboard/app.py)에서 import해서 사용.

기능:
- 자연어 시간 범위 파싱
- SQLite Alert 조회 + 통계 집계
- OpenAI Responses API로 보고서 생성 (Web Search 툴 포함)

전제:
- ids_service/.env 파일에 OPENAI_API_KEY 설정 필요
"""

import os
import json
import sys
from pathlib import Path
from datetime import datetime, timedelta

from dotenv import load_dotenv
from openai import OpenAI

# 상위 폴더(ids_service/)를 파이썬 경로에 추가
sys.path.append(str(Path(__file__).parent.parent))

from db.database import get_connection


# ============================================================
# 설정
# ============================================================

load_dotenv(Path(__file__).parent.parent / ".env")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

# OpenAI 호스팅 툴: Web Search
tools = [
    {
        "type": "web_search",
        "search_context_size": "medium",
        "user_location": {
            "type": "approximate",
            "country": "KR",
            "city": "Seoul",
            "region": "Seoul",
        }
    }
]


# ============================================================
# DB 조회 함수
# ============================================================

def get_alerts_between(start_time: datetime, end_time: datetime):
    """지정한 시간 범위의 Alert를 최신순으로 조회"""
    conn = get_connection()
    rows = conn.execute("""
        SELECT *
        FROM alerts
        WHERE timestamp BETWEEN ? AND ?
        ORDER BY timestamp DESC
    """, (
        start_time.isoformat(timespec="seconds"),
        end_time.isoformat(timespec="seconds")
    )).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_alert_summary(hours: int):
    """
    최근 N시간 Alert를 조회하고 보고서용 통계 집계
    """
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=hours)

    alerts = get_alerts_between(start_time, end_time)

    summary = {
        "hours": hours,
        "start_time": start_time.isoformat(timespec="seconds"),
        "end_time": end_time.isoformat(timespec="seconds"),
        "total_alerts": len(alerts),
        "risk_level_count": {},
        "attack_type_count": {},
        "protocol_count": {},
        "detection_type_count": {},
        "top_src_ips": {},
        "top_dst_ports": {}
    }

    for alert in alerts:
        risk = alert.get("risk_level") or "UNKNOWN"
        attack = alert.get("attack_type") or "UNKNOWN"
        protocol = alert.get("protocol") or "UNKNOWN"
        detection_type = alert.get("detection_type") or "UNKNOWN"
        src_ip = alert.get("src_ip") or "UNKNOWN"
        dst_port = str(alert.get("dst_port") or "UNKNOWN")

        summary["risk_level_count"][risk] = summary["risk_level_count"].get(risk, 0) + 1
        summary["attack_type_count"][attack] = summary["attack_type_count"].get(attack, 0) + 1
        summary["protocol_count"][protocol] = summary["protocol_count"].get(protocol, 0) + 1
        summary["detection_type_count"][detection_type] = summary["detection_type_count"].get(detection_type, 0) + 1
        summary["top_src_ips"][src_ip] = summary["top_src_ips"].get(src_ip, 0) + 1
        summary["top_dst_ports"][dst_port] = summary["top_dst_ports"].get(dst_port, 0) + 1

    return {
        "summary": summary,
        "alerts": alerts
    }


# ============================================================
# 자연어 파싱
# ============================================================

def extract_hours(user_message: str) -> int:
    """사용자 질문에서 조회 시간 범위 추출 (기본 3시간)"""
    default_hours = 3

    tokens = (
        user_message
        .replace("동안", " ")
        .replace("최근", " ")
        .replace("시간", " 시간 ")
        .split()
    )

    for idx, token in enumerate(tokens):
        if token.isdigit():
            return int(token)
        if token.endswith("시간"):
            number = token.replace("시간", "")
            if number.isdigit():
                return int(number)
        if token == "시간" and idx > 0 and tokens[idx - 1].isdigit():
            return int(tokens[idx - 1])

    return default_hours


# ============================================================
# 보고서 생성 (OpenAI Responses API)
# ============================================================

def generate_report(user_message: str) -> str:
    """
    사용자 질문 → DB 조회 → LLM 보고서 생성
    
    Args:
        user_message: 사용자가 입력한 자연어 질문
    
    Returns:
        LLM이 생성한 보고서 텍스트 (한국어)
    """
    hours = extract_hours(user_message)
    data = get_alert_summary(hours)

    client = OpenAI(api_key=OPENAI_API_KEY)

    prompt = f"""
너는 실시간 침입 탐지 시스템의 보안 분석 챗봇이다.

사용자 요청:
{user_message}

분석 기준 시각:
- 시작 시각: {data["summary"]["start_time"]}
- 종료 시각: {data["summary"]["end_time"]}
- 분석 범위: 최근 {hours}시간

아래는 해당 분석 기간 동안 SQLite에서 조회한 Alert 데이터다.

데이터:
{json.dumps(data, ensure_ascii=False, indent=2)}

다음 형식으로 한국어 보안 보고서를 작성해라.

1. 분석 기간
2. 전체 Alert 요약
3. 위험도별 분포
4. 공격 유형별 분포
5. 탐지 방식별 분포
6. 주요 공격 출발지 IP
7. 주요 대상 포트
8. 주요 위험 이벤트
9. 대응 권고사항

주의:
- 분석 기간은 반드시 위의 시작 시각과 종료 시각을 그대로 사용해 작성할 것
- 현재 시각이나 분석 기간을 임의로 계산하지 말 것
- 데이터에 없는 내용은 추측하지 말 것
- Alert가 없으면 Alert가 없다고 명확히 말할 것
- description 필드가 있으면 주요 위험 이벤트 설명에 반영할 것
- 대응 권고는 실무적으로 간단명료하게 작성할 것
- 대응 권고사항을 작성할 때는 attack_type을 기준으로 최신 보안 대응 지침을 Web Search로 확인할 것
- 검색 결과를 사용할 경우 출처를 간단히 함께 언급할 것
"""

    response = client.responses.create(
        model=MODEL,
        tools=tools,
        input=prompt
    )

    return response.output_text