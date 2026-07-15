"""
IDS 챗봇 로직 (Function Calling 기반)

원본: 병규님 chatbot0_3v.py
수정: 우리 프로젝트 구조에 맞게 통합
- DB: db.database.get_connection() 재사용
- .env: ids_service/.env 절대 경로 로드
- Streamlit UI 코드는 dashboard/app.py로 이동 (여기는 순수 로직만)

기능:
- OpenAI Responses API + Function Calling
- 3개 커스텀 툴 (get_latest_alerts, get_alert_summary, get_alerts_by_type)
- Web Search 호스팅 툴
- 대화 히스토리 + 이전 DB 조회 결과 컨텍스트 관리
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

# ids_service/.env 절대 경로 로드
load_dotenv(Path(__file__).parent.parent / ".env")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

# Web Search 도구명 (SDK/계정 환경에 따라 다를 수 있음)
# 오류 시 .env에 OPENAI_WEB_SEARCH_TOOL=web_search 로 바꿔서 테스트
WEB_SEARCH_TOOL = os.getenv("OPENAI_WEB_SEARCH_TOOL", "web_search_preview")


# ============================================================
# Function Calling 툴 등록
# ============================================================
tools = [
    {
        "type": "function",
        "name": "get_latest_alerts",
        "description": "SQLite DB에서 가장 최근에 발생한 Alert N건을 조회한다. 사용자가 '최근 3건', '최근 5개', '최신 10건'처럼 요청할 때 사용한다.",
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "조회할 최근 Alert 개수. 기본값은 3이다."
                }
            },
            "required": ["limit"],
            "additionalProperties": False
        }
    },
    {
        "type": "function",
        "name": "get_alert_summary",
        "description": "SQLite DB에서 최근 N시간 동안의 Alert 목록과 요약 통계를 조회한다. 사용자가 '최근 3시간 보고서', '최근 1시간 요약'처럼 요청할 때 사용한다.",
        "parameters": {
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer",
                    "description": "조회할 시간 범위. 예: 최근 3시간이면 3."
                }
            },
            "required": ["hours"],
            "additionalProperties": False
        }
    },
    {
        "type": WEB_SEARCH_TOOL,
        "search_context_size": "medium",
        "user_location": {
            "type": "approximate",
            "country": "KR",
            "city": "Seoul",
            "region": "Seoul"
        }
    },
    {
        "type": "function",
        "name": "get_alerts_by_type",
        "description": "SQLite DB에서 특정 공격 유형에 해당하는 Alert를 최신순으로 조회한다. 사용자가 'SSH Brute Force만 보여줘', 'Web Attack 공격 조회해줘', 'HTTP Flood 대응 방안 알려줘'처럼 공격 유형을 기준으로 요청할 때 사용한다.",
        "parameters": {
            "type": "object",
            "properties": {
                "attack_type": {
                    "type": "string",
                    "description": "조회할 공격 유형. 예: SSH Brute Force, Web Attack, HTTP Flood"
                },
                "limit": {
                    "type": "integer",
                    "description": "조회할 최대 Alert 개수. 기본값은 10이다."
                }
            },
            "required": ["attack_type", "limit"],
            "additionalProperties": False
        }
    }
]


# ============================================================
# DB 조회 함수 (get_connection() 재사용)
# ============================================================

def get_alerts_between(start_time: datetime, end_time: datetime):
    """
    지정한 시작 시각과 종료 시각 사이의 Alert를 조회한다.
    get_alert_summary() 내부에서 사용하는 보조 함수다.
    """
    conn = get_connection()  # 우리 database.py 함수 재사용
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


def get_latest_alerts(limit: int = 3):
    """
    가장 최근에 발생한 Alert N건을 조회한다.
    Function Calling에서 '최근 3건', '최신 5개' 같은 요청을 처리한다.
    """
    # 너무 많은 데이터를 한 번에 가져오지 않도록 1~50 사이로 제한
    limit = max(1, min(int(limit), 50))

    conn = get_connection()
    rows = conn.execute("""
        SELECT *
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()

    return {
        "request_type": "recent_alerts",
        "limit": limit,
        "alerts": [dict(row) for row in rows]
    }


def get_alert_summary(hours: int = 3):
    """
    최근 N시간 동안의 Alert를 조회하고,
    보고서 생성에 필요한 통계 데이터를 만든다.
    """
    # 조회 범위를 1~24시간으로 제한
    hours = max(1, min(int(hours), 24))

    # 분석 기간은 LLM이 아니라 Python에서 직접 계산 (오차 방지)
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

    # 통계 누적
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
        "request_type": "alert_summary",
        "summary": summary,
        "alerts": alerts
    }


def get_alerts_by_type(attack_type: str, limit: int = 10):
    """
    특정 공격 유형에 해당하는 Alert를 최신순으로 조회한다.
    """
    limit = max(1, min(int(limit), 50))

    conn = get_connection()
    # LIKE 검색으로 부분 일치 지원 (예: 'SSH'만 입력해도 'SSH Brute Force' 찾음)
    rows = conn.execute("""
        SELECT *
        FROM alerts
        WHERE attack_type LIKE ?
        ORDER BY timestamp DESC
        LIMIT ?
    """, (
        f"%{attack_type}%",
        limit
    )).fetchall()
    conn.close()

    return {
        "request_type": "alerts_by_type",
        "attack_type": attack_type,
        "limit": limit,
        "alerts": [dict(row) for row in rows]
    }


# ============================================================
# Function Calling 라우터
# ============================================================

def run_local_tool(tool_name: str, arguments: dict):
    """
    모델이 Function Calling으로 요청한 로컬 함수를 실제 Python 함수에 연결한다.
    """
    if tool_name == "get_latest_alerts":
        return get_latest_alerts(
            limit=arguments.get("limit", 3)
        )

    if tool_name == "get_alert_summary":
        return get_alert_summary(
            hours=arguments.get("hours", 3)
        )

    if tool_name == "get_alerts_by_type":
        return get_alerts_by_type(
            attack_type=arguments.get("attack_type", ""),
            limit=arguments.get("limit", 10)
        )

    return {
        "error": f"Unknown tool: {tool_name}"
    }


# ============================================================
# 모델 입력 구성 (대화 히스토리 + 이전 조회 결과)
# ============================================================

def build_model_input(user_message: str, previous_context=None, conversation_context=None):
    """
    모델에게 전달할 input을 구성한다.

    conversation_context: 최근 대화 기록 ('아까 말한 것' 이해용)
    previous_context: 마지막 Function Calling 결과 원본 ('그걸' 이해용)
    """
    model_input = []

    # 최근 대화 기록
    if conversation_context:
        for message in conversation_context:
            model_input.append({
                "role": message["role"],
                "content": message["content"]
            })

    # 마지막 DB 조회 결과
    if previous_context:
        model_input.append({
            "role": "user",
            "content": f"""
이전 DB 조회 결과:
{json.dumps(previous_context, ensure_ascii=False, indent=2)}

사용자가 '그걸', '방금 것', '방금 조회한 Alert', '위 내용', '이 Alert', '두 번째 Alert'처럼 말하면
위 이전 DB 조회 결과를 우선 기준으로 삼아라.
"""
        })

    # 현재 사용자 요청
    model_input.append({
        "role": "user",
        "content": user_message
    })

    return model_input


# ============================================================
# 시스템 지침 (프롬프트)
# ============================================================

INSTRUCTIONS = """
너는 실시간 침입 탐지 시스템의 보안 분석 챗봇이다.

반드시 다음 규칙을 따라라.

1. 사용자가 '최근 N건', '최근 N개', '최신 N건'처럼 개수를 말하면 get_latest_alerts 함수를 호출해라.
2. 사용자가 '최근 N시간', 'N시간 동안', '요약'처럼 시간 범위를 말하면 get_alert_summary 함수를 호출해라.
3. 사용자가 '보고서', '리포트', 'Notion 형식', '노션 형식', '문서로 정리'처럼 보고서 작성을 요청하면 관련 함수를 호출한 뒤 Notion Markdown 보고서 형식으로 작성해라.
4. 사용자가 개수나 시간을 명확히 말하지 않고 최근 Alert를 물으면 get_latest_alerts(limit=3)을 호출해라.
5. DB에 없는 Alert 탐지 결과는 탐지되지 않았다고 명확히 말해라.
   단, 사용자가 특정 공격 유형을 물어본 경우 해당 공격이 DB에서 탐지되지 않았더라도 Web Search를 사용해 공격 개념, 동작 방식, 주요 피해, 대응 방안을 설명해라.
6. 대응 권고사항을 작성할 때는 attack_type과 dst_port를 기준으로 작성해라.
7. 최신 대응 지침이 필요한 경우 Web Search를 사용해도 된다.
8. Web Search를 사용한 경우 출처를 간단히 언급해라.
9. 사용자가 특정 공격 유형을 언급하며 조회, 분석, 대응 방안을 요청하면 get_alerts_by_type 함수를 호출해라.
   예: SSH Brute Force, Web Attack, HTTP Flood, Port Scan, DDoS, Ransomware
10. get_alerts_by_type 호출 결과 alerts가 빈 리스트이면 다음 형식으로 답변해라.
    - 현재 SQLite Alert DB에서는 해당 공격 유형이 탐지되지 않았다고 말할 것
    - 그러나 Web Search를 통해 해당 공격 유형의 개념과 일반적인 대응 방안을 설명할 것
    - 탐지 결과와 일반 보안 지식을 구분해서 작성할 것
11. 사용자가 '그걸', '방금 것', '위 내용', '이 Alert', '두 번째 Alert'처럼 이전 내용을 가리키면,
    새로 DB를 조회하기보다 이전 DB 조회 결과와 대화 기록을 우선 기준으로 답변해라.
12. 이전 DB 조회 결과만으로 기준 대상을 확정할 수 없으면, 임의로 추측하지 말고 어떤 Alert를 기준으로 할지 물어봐라.
13. 데이터에 없는 값은 'N/A'로 표시하고, DB에 존재하지 않는 Alert를 만들어내지 마라.

일반 응답 형식:
- 사용자가 단순히 '최근 N건 보여줘', '최근 N개 조회해줘', 'SSH Brute Force 공격만 보여줘'처럼 조회를 요청하면 보고서 형식으로 작성하지 마라.
- 일반 조회 응답은 짧고 읽기 쉽게 bullet 형식으로 작성해라.
- 각 Alert는 번호별로 정리하되, 번호 옆 제목에 alert_id를 반드시 표시해라.
  예: 1. model-b7e5d234
- 각 Alert에는 alert_id, 발생 시각, 공격 유형, 위험도, 출발지 IP, 목적지 IP, 대상 포트, 탐지 방식, 설명을 포함해라.
- alert_id가 없으면 번호 옆에 "N/A"를 표시해라.
- 마지막에 간단한 대응 권고사항을 2~3개만 작성해라.

보고서 작성 형식:
- 사용자가 '보고서', '리포트', 'Notion', '노션', '문서로 정리', '보고서 작성'을 명시적으로 요청한 경우에만 아래 Notion Markdown 템플릿을 사용해라.
- Notion에 있는 이모지, 콜아웃 등을 자유롭게 사용하여 보고서를 작성해라
- 보고서는 Notion에 바로 복사/붙여넣기 가능한 Markdown 형식으로 작성해라.
- 불필요한 인사말, 사족, 코드블록 없이 보고서 본문만 출력해라.

# 침입 탐지 분석 보고서

## 1. 분석 개요
- 분석 기준:
- 분석 대상:
- 조회 범위:
- 전체 Alert 수:

## 2. 핵심 요약
- 주요 공격 유형:
- 최고 위험도:
- 주요 출발지 IP:
- 주요 대상 포트:
- 종합 판단:

## 3. Alert 상세 내역

| No | 발생 시각 | 공격 유형 | 위험도 | 출발지 IP | 목적지 IP | 대상 포트 | 탐지 방식 | 신뢰도 |
|---|---|---|---|---|---|---|---|---|

## 4. 공격 패턴 분석
- 반복적으로 관찰된 패턴:
- 의심되는 공격 목적:
- 관련 위험 포트:
- 추가 확인이 필요한 로그:

## 5. 위험도 평가
- 전체 위험도:
- 판단 근거:
- 우선 대응 대상:

## 6. 대응 권고사항
- [ ] 
- [ ] 
- [ ] 

## 7. 추가 조사 항목
- [ ] 
- [ ] 

## 8. 참고 출처
- Web Search를 사용한 경우 출처를 적어라.
- Web Search를 사용하지 않은 경우 '내부 Alert DB 기반 분석'이라고 적어라.

공격 유형이 DB에서 탐지되지 않은 경우:
- 사용자가 보고서를 요청하지 않았다면 일반 설명 형식으로 답변해라.
- 사용자가 보고서를 요청했다면 아래 템플릿을 사용해라.

# 공격 유형 분석 보고서

## 1. 탐지 여부
- 요청한 공격 유형:
- 내부 Alert DB 탐지 여부: 탐지되지 않음

## 2. 공격 개념
-

## 3. 일반적인 공격 방식
-

## 4. 주요 피해
-

## 5. 대응 방안
- [ ] 
- [ ] 
- [ ] 

## 6. 참고 출처
-

공통 주의사항:
- 보고서 작성 요청이 아닐 때는 Notion 보고서 템플릿을 사용하지 마라.
- 보고서 작성 요청일 때만 제목, 표, 체크박스를 포함한 Markdown 보고서를 작성해라.
- Alert 상세 내역 표에는 실제 조회된 Alert만 작성해라.
- DB에 존재하지 않는 Alert, IP, 포트, confidence 값을 만들어내지 마라.
"""


# ============================================================
# 메인 함수: generate_report
# ============================================================

def generate_report(user_message: str, previous_context=None, conversation_context=None):
    """
    사용자 질문 -> Function Calling -> LLM 응답 생성

    Args:
        user_message: 사용자 입력
        previous_context: 마지막 DB 조회 결과 (지시대명사 처리용)
        conversation_context: 최근 대화 기록 (문맥 이해용)

    Returns:
        (answer, latest_tool_context) 튜플
        - answer: LLM 최종 응답 텍스트
        - latest_tool_context: 이번 호출에서 실행된 마지막 tool 결과 (다음 호출 시 previous_context로 재사용)
    """
    client = OpenAI(api_key=OPENAI_API_KEY)

    # 대화 기록 + 이전 조회 결과 + 현재 질문 조합
    model_input = build_model_input(
        user_message=user_message,
        previous_context=previous_context,
        conversation_context=conversation_context
    )

    # 1차 호출
    response = client.responses.create(
        model=MODEL,
        instructions=INSTRUCTIONS,
        tools=tools,
        input=model_input
    )

    # 기본은 이전 context 유지
    latest_tool_context = previous_context

    # Function Calling 처리 loop (최대 5회)
    for _ in range(5):
        function_outputs = []

        # function_call 항목만 골라서 실행
        for item in response.output:
            if item.type == "function_call":
                arguments = json.loads(item.arguments or "{}")

                # 실제 Python 함수 실행
                result = run_local_tool(item.name, arguments)

                # 다음 사용자 질문에서 재사용 가능하게 저장
                latest_tool_context = {
                    "tool_name": item.name,
                    "arguments": arguments,
                    "result": result
                }

                # 모델에게 돌려줄 function_call_output 생성
                function_outputs.append({
                    "type": "function_call_output",
                    "call_id": item.call_id,
                    "output": json.dumps(result, ensure_ascii=False)
                })

        # 더 실행할 함수 없으면 종료
        if not function_outputs:
            break

        # 함수 실행 결과를 모델에게 다시 전달
        response = client.responses.create(
            model=MODEL,
            instructions=INSTRUCTIONS,
            tools=tools,
            previous_response_id=response.id,
            input=function_outputs
        )

    return response.output_text, latest_tool_context