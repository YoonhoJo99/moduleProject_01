"""
IDS 실시간 모니터링 대시보드 + 챗봇 (Streamlit 통합 앱)

실행 방법:
    streamlit run dashboard/app.py

접속: http://localhost:8501

구조:
- 좌측 2/3: 대시보드 (자동 갱신)..
- 우측 1/3: 챗봇 (Function Calling 기반)
"""

import sqlite3
import sys
from pathlib import Path
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

# 상위 폴더(ids_service/)를 파이썬 경로에 추가
sys.path.append(str(Path(__file__).parent.parent))

from chatbot.agent import generate_report, OPENAI_API_KEY, MODEL


# ============================================================
# 설정
# ============================================================

DB_PATH = Path(__file__).parent.parent / "db" / "alerts.db"
REFRESH_INTERVAL = 5


# ============================================================
# 페이지 기본 설정
# ============================================================
st.set_page_config(
    page_title="IDS 실시간 모니터링",
    page_icon="🛡",
    layout="wide",
)


# ============================================================
# DB 조회 함수 (대시보드용)
# ============================================================

def load_alerts(limit: int = 500) -> pd.DataFrame:
    if not DB_PATH.exists():
        return pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        f"SELECT * FROM alerts ORDER BY timestamp DESC LIMIT {limit}",
        conn,
    )
    conn.close()
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


# ============================================================
# 상단: 제목 (고정)
# ============================================================
st.title("🛡 IDS 실시간 모니터링 대시보드")
st.caption(f"머신러닝 기반 실시간 네트워크 침입 탐지 시스템 | ⚡ 대시보드 {REFRESH_INTERVAL}초 자동 갱신")


# ============================================================
# 좌우 2단 레이아웃
# ============================================================
main_col, chatbot_col = st.columns([2, 1], gap="large")


# ============================================================
# 왼쪽: 대시보드 (자동 갱신 영역)
# ============================================================
with main_col:

    @st.fragment(run_every=REFRESH_INTERVAL)
    def realtime_dashboard():
        df = load_alerts(limit=500)

        if df.empty:
            st.warning("⚠ 아직 수집된 Alert가 없습니다. FastAPI 서버와 가짜 생성기를 실행해주세요.")
            return

        # 📊 요약 지표
        top_col1, top_col2 = st.columns([3, 1])
        with top_col1:
            st.subheader("📊 요약 지표")
        with top_col2:
            st.markdown(
                f"<p style='text-align: right; color: gray; padding-top: 20px;'>"
                f"🕐 마지막 갱신: <b>{datetime.now().strftime('%H:%M:%S')}</b></p>",
                unsafe_allow_html=True,
            )

        col1, col2, col3, col4 = st.columns(4)
        total_count = len(df)
        col1.metric(label="🚨 총 Alert", value=f"{total_count:,}")
        high_count = len(df[df["risk_level"] == "HIGH"])
        col2.metric(
            label="🔴 HIGH 위험",
            value=f"{high_count:,}",
            delta=f"{high_count / total_count * 100:.1f}%",
        )
        medium_count = len(df[df["risk_level"] == "MEDIUM"])
        col3.metric(
            label="🟡 MEDIUM 위험",
            value=f"{medium_count:,}",
            delta=f"{medium_count / total_count * 100:.1f}%",
        )
        rule_count = len(df[df["detection_type"] == "Rule"])
        model_count = len(df[df["detection_type"] == "Model"])
        col4.metric(label="🔍 Rule : Model", value=f"{rule_count} : {model_count}")

        st.divider()

        # 📈 차트 (좌우 2단)
        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            st.subheader("📈 분 단위 Alert 발생 추이")
            df_time = df.copy()
            df_time["minute"] = df_time["timestamp"].dt.floor("1min")
            time_series = (
                df_time.groupby(["minute", "risk_level"])
                .size()
                .reset_index(name="count")
            )
            fig_line = px.line(
                time_series, x="minute", y="count", color="risk_level", markers=True,
                color_discrete_map={"HIGH": "#EF4444", "MEDIUM": "#F59E0B"},
                labels={"minute": "시각", "count": "Alert 수", "risk_level": "위험도"},
            )
            fig_line.update_layout(
                height=300, margin=dict(l=20, r=20, t=30, b=20),
                legend=dict(orientation="h", y=1.1),
            )
            st.plotly_chart(fig_line, use_container_width=True)

        with chart_col2:
            st.subheader("🥧 공격 유형 분포")
            attack_counts = df["attack_type"].value_counts().reset_index()
            attack_counts.columns = ["공격 유형", "건수"]
            fig_pie = px.pie(attack_counts, values="건수", names="공격 유형", hole=0.4)
            fig_pie.update_traces(textposition="inside", textinfo="percent+label")
            fig_pie.update_layout(
                height=300, margin=dict(l=20, r=20, t=30, b=20), showlegend=False,
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        st.divider()

        # 🚨 실시간 테이블
        st.subheader("🚨 최근 Alert (실시간)")
        display_df = df[[
            "timestamp", "detection_type", "attack_type", "risk_level",
            "confidence", "src_ip", "dst_ip", "dst_port", "protocol", "description",
        ]].copy()
        display_df.columns = [
            "시각", "탐지 방식", "공격 유형", "위험도", "신뢰도",
            "출발 IP", "대상 IP", "대상 포트", "프로토콜", "설명",
        ]
        display_df["시각"] = display_df["시각"].dt.strftime("%m-%d %H:%M:%S")
        st.dataframe(
            display_df, use_container_width=True, height=350, hide_index=True,
        )
        st.caption(f"💡 최근 {len(df)}건 표시 중")

    realtime_dashboard()


# ============================================================
# 오른쪽: 챗봇 (Function Calling 기반)
# ============================================================
with chatbot_col:
    st.subheader("💬 보안 챗봇")
    st.caption("자연어로 질문하면 LLM이 필요한 함수를 스스로 호출합니다.")

    # API Key 검증
    if not OPENAI_API_KEY:
        st.error("⚠ .env 파일에 OPENAI_API_KEY를 설정해주세요.")
        st.stop()

    # 챗봇 예시 질문
    with st.expander("💡 예시 질문 보기"):
        st.code("최근 3건 Alert 보여줘")
        st.code("SSH Brute Force 공격만 보여줘")
        st.code("최근 3시간 동안의 트래픽 기반으로 보고서 작성해줘")
        st.code("최근 1시간 Alert 요약해줘")

    st.caption(f"🤖 모델: `{MODEL}` | 🔧 Web Search + Function Calling")

    # ------------------------------------------------------------
    # 세션 상태 초기화
    # ------------------------------------------------------------
    
    # 대화 히스토리
    if "messages" not in st.session_state:
        st.session_state.messages = []
    
    # 마지막 Function Calling 결과 (지시대명사 처리용)
    # 예: 사용자가 "그걸", "방금 것"이라고 물었을 때 참조
    if "last_tool_context" not in st.session_state:
        st.session_state.last_tool_context = None

    # ------------------------------------------------------------
    # 대화창 (스크롤 가능한 컨테이너)
    # ------------------------------------------------------------
    chat_container = st.container(height=500)

    with chat_container:
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])

                if message["role"] == "assistant":
                    st.download_button(
                        label="답변 다운로드",
                        data=message["content"],
                        file_name=f"ids_chatbot_answer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                        mime="text/markdown",
                        key=f"download_history_{id(message)}",
                    )

    # ------------------------------------------------------------
    # 사용자 입력 처리
    # ------------------------------------------------------------
    user_input = st.chat_input("예: 최근 3건 Alert 보여줘")

    if user_input:
        # 최근 6개 대화 히스토리 (문맥 이해용)
        conversation_context = st.session_state.messages[-6:]

        # 사용자 메시지 저장
        st.session_state.messages.append({"role": "user", "content": user_input})

        # 대화창에 표시
        with chat_container:
            with st.chat_message("user"):
                st.write(user_input)

            # 챗봇 응답 생성
            with st.chat_message("assistant"):
                with st.spinner("누구보다 열심히 찾아보는중..."):
                    try:
                        # Function Calling + 대화 컨텍스트 전달
                        answer, latest_context = generate_report(
                            user_message=user_input,
                            previous_context=st.session_state.last_tool_context,
                            conversation_context=conversation_context,
                        )
                        st.write(answer)

                        st.download_button(
                            label="답변 다운로드",
                            data=answer,
                            file_name=f"ids_chatbot_answer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                            mime="text/markdown",
                            key=f"download_current_{len(st.session_state.messages)}",
                        )

                        # 새로운 tool 결과가 있으면 저장 (다음 질문에 활용)
                        if latest_context:
                            st.session_state.last_tool_context = latest_context

                    except Exception as e:
                        answer = f"⚠ 보고서 생성 중 오류가 발생했습니다: {e}"
                        st.error(answer)

        # 응답을 히스토리에 저장
        st.session_state.messages.append({"role": "assistant", "content": answer})
