# IDS Service

머신러닝 기반 실시간 네트워크 침입 탐지 시스템의 **백엔드 · 대시보드 · 챗봇** 서비스.

앞팀(패킷 캡처 → 예측 서버)에서 전송한 Alert JSON을 수신하고, SQLite에 저장하며, 실시간 대시보드와 OpenAI 기반 챗봇을 통해 사용자에게 시각적/대화형 인터페이스를 제공한다.

본 문서는 팀원들이 각자 로컬 환경에서 `ids_service`를 실행하고 테스트할 수 있도록 설치·실행 방법을 안내한다.



---

## 📋 목차

1. [프로젝트 구조]
2. [사전 준비]
3. [최초 세팅]
4. [실행 방법]
5. [주요 URL]
6. [팀원 정보 (담당자)]
7. [문제 해결 (FAQ)]

---

## 📁 프로젝트 구조

```
ids_service/
├── main.py                    # FastAPI 서버 (Alert 수신)
├── requirements.txt           # 필요 패키지 목록
├── .env                       # 환경변수 (직접 생성 필요, git 제외)
│
├── db/
│   ├── database.py            # SQLite 연결/저장 함수
│   └── alerts.db              # SQLite DB (자동 생성, git 제외)
│
├── dashboard/
│   └── app.py                 # Streamlit 통합 앱 (대시보드 + 챗봇)
│
├── chatbot/
│   └── agent.py               # 챗봇 로직 (OpenAI + Web Search)
│
└── mock/
    └── fake_sender.py         # 개발용 가짜 Alert 생성기
```

---

## 🛠 사전 준비

### 필수 사항

- **Python 3.10 이상** 설치되어 있어야 함
- **Git 설치** (프로젝트 clone용)
- **OpenAI API 키** (챗봇 사용 시 필요)

### 확인 방법

```bash
python --version
# 또는
python3 --version
```

`Python 3.10.x` 이상이면 정상.

---

## 🚀 최초 세팅

**처음 로컬에서 실행할 때 한 번만 하면 됨.**

### 1. 프로젝트 clone

```bash
git clone <레포지토리 URL>
cd moduleProject_01/ids_service
```

### 2. Python 가상환경 생성

```bash
python -m venv venv
```

`venv/` 폴더가 생기면 성공.

### 3. 가상환경 활성화

**Windows (Git Bash / MINGW64):**

```bash
source venv/Scripts/activate
```

**Windows (CMD):**

```cmd
venv\Scripts\activate
```

**Windows (PowerShell):**

```powershell
venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
source venv/bin/activate
```

**성공 표시:** 프롬프트 앞에 `(venv)` 표시가 붙는다.

### 4. 필요 패키지 설치

```bash
pip install -r requirements.txt
```

`fastapi`, `uvicorn`, `streamlit`, `openai`, `python-dotenv`, `pandas`, `plotly` 등이 자동 설치됨.

### 5. `.env` 파일 생성

**`ids_service/.env`** 파일을 새로 만들고 아래 내용 입력:

```
OPENAI_API_KEY=여기에_실제_API_키_입력
OPENAI_MODEL=gpt-5.5
```

**⚠️ 주의:**

- `=` 앞뒤에 공백 없어야 함
- 값에 따옴표(`"`) 넣지 말 것
- `.env` 파일은 `.gitignore`에 등록되어 있어 GitHub에 안 올라감

**API 키 없이 챗봇 없이 실행하고 싶다면?** `.env` 없이도 대시보드는 정상 작동함 (챗봇 부분만 오류 메시지 표시).

---

## ▶ 실행 방법

**터미널 3개**를 열어서 각각 실행해야 한다.

**⚠️ 모든 터미널에서:**

1. `cd ids_service` 로 이동
2. 가상환경 활성화 (`source venv/Scripts/activate` 등)

---

### 터미널 1️⃣ — FastAPI 서버 (백엔드)

**역할:** Alert JSON 수신 → SQLite 저장

```bash
uvicorn main:app --reload
```

**성공 화면:**

```
[DB] 초기화 완료: .../db/alerts.db
INFO:     Uvicorn running on http://127.0.0.1:8000
```

---

### 터미널 2️⃣ — 가짜 Alert 생성기 (개발용)

**역할:** 랜덤 Alert JSON을 FastAPI 서버로 계속 전송 (실제 앞팀 서버 대체)

```bash
python mock/fake_sender.py
```

**성공 화면:**

```
🚀 가짜 Alert 생성기 시작
   대상 서버: http://127.0.0.1:8000/alerts
✓ [Rule] rule-a3f2c891 | SSH Brute Force | HIGH
✓ [Model] model-b7e5d234 | Web Attack | MEDIUM
...
```

**참고:** 이 터미널은 앞팀 예측 서버가 실제로 연결되면 필요 없어짐.

---

### 터미널 3️⃣ — Streamlit 통합 앱 (대시보드 + 챗봇)

**역할:** 웹 UI 제공

```bash
streamlit run dashboard/app.py
```

**성공 화면:**

```
You can now view your Streamlit app in your browser.
Local URL: http://localhost:8501
```

브라우저가 자동으로 열림. 안 열리면 수동으로 `http://localhost:8501` 접속.

---

## 🌐 주요 URL

| URL                            | 용도                       |
| ------------------------------ | ------------------------ |
| `http://localhost:8501`        | **메인 화면** (대시보드 + 챗봇 통합) |
| `http://127.0.0.1:8000`        | FastAPI 서버 헬스체크          |
| `http://127.0.0.1:8000/docs`   | API 자동 문서 (Swagger UI)   |
| `http://127.0.0.1:8000/alerts` | 저장된 Alert 조회             |


## 🛑 종료 방법

각 터미널에서 `Ctrl + C`

---

## 👥 팀원 정보 

**담당:** 
	백엔드 · 대시보드 : 조윤호
	챗봇 : 정병규

**주요 기술:**

- FastAPI, SQLite, Pydantic
- Streamlit, Plotly, pandas
- OpenAI Responses API + Web Search (호스팅 툴)

**연동 지점:**

- 앞팀 서버 → `POST /alerts` (JSON) → 우리 서버
- 통신 방식: Tailscale (예정)

---

## 🧪 챗봇 테스트 예시 (function calling 도입 후 수정 예정)

브라우저에서 우측 챗봇 영역에 입력:

```
최근 3시간 동안의 트래픽 기반으로 보고서 작성해줘
```

```
최근 1시간 Alert 요약해줘
```

```
최근 6시간 주요 공격 IP 알려줘
```

**응답 시간:** 10~30초 (Web Search 툴 사용 시간 포함)

---

## ❓ 문제 해결 (FAQ)

### Q1. `venv\Scripts\activate` 명령어가 안 먹힘

**증상 (Git Bash):**

```
bash: venvScriptsactivate: command not found
```


**해결:** Git Bash에서는 슬래시 방식으로:

```bash
source venv/Scripts/activate
```

---

### Q2. `uvicorn: command not found` 에러

**원인 2가지:**

1. `ids_service/` 폴더가 아닌 다른 위치에서 실행
2. 가상환경 활성화 안 됨 (프롬프트에 `(venv)` 없음)

**해결:**

```bash
cd ids_service
source venv/Scripts/activate
uvicorn main:app --reload
```

---

### Q3. VS Code에서 `Import "fastapi" could not be resolved` 경고

**원인:** VS Code Pylance가 venv를 못 찾음

**해결:**

1. `Ctrl + Shift + P` → `Python: Select Interpreter`
2. venv 경로가 포함된 인터프리터 선택
    - 예: `Python 3.x.x ('venv': venv)`

---

### Q4. Streamlit 첫 실행 시 이메일 입력 요청

```
Welcome to Streamlit!
Email:
```

**해결:** 그냥 `Enter` 누르고 넘어감 (이메일 안 넣어도 됨).

---

### Q5. 챗봇 응답 중 대시보드가 멈춤

**증상:** 챗봇 응답 대기 중 좌측 대시보드 자동 갱신이 중단됨

**원인:** Streamlit의 단일 스레드 특성 (알려진 이슈)

**해결:** 챗봇 응답 완료 후 대시보드 갱신이 재개됨. 정상 동작.

---

### Q6. `.env` 없이 실행하면?

- 대시보드: 정상 작동
- 챗봇: `⚠ ids_service/.env 파일에 OPENAI_API_KEY를 설정해주세요` 메시지 표시

`.env` 파일을 만들고 재시작하면 챗봇도 동작.

---

### Q7. 가짜 생성기 안 돌리고 대시보드 보고 싶은데 데이터가 없음

**증상:**

```
⚠ 아직 수집된 Alert가 없습니다.
```

**해결:** 터미널 2에서 `python mock/fake_sender.py` 실행. 5~10초 정도 데이터 쌓인 후 대시보드 확인.

---

### Q8. 포트 이미 사용 중 에러

**증상:**

```
Address already in use
```

**해결:** 다른 프로세스에서 8000번(FastAPI) 또는 8501번(Streamlit) 포트 사용 중.

- 다른 터미널에서 실행 중인지 확인 후 종료
- 또는 다른 포트로 실행:
    
    ```bash
    uvicorn main:app --reload --port 8001streamlit run dashboard/app.py --server.port 8502
    ```
    

---

## 📝 개발 참고

### DB 초기화하고 싶을 때

```bash
# ids_service/db/alerts.db 파일 삭제
rm db/alerts.db

# FastAPI 서버 재시작하면 자동으로 새 DB 생성됨
```

### 패키지 새로 추가한 경우

```bash
pip install <패키지명>
pip freeze > requirements.txt
git add requirements.txt
git commit -m "chore: 패키지 추가"
```

---

## 🔗 관련 링크

- 프로젝트 전체 저장소: (팀 GitHub URL)
- FastAPI 문서: https://fastapi.tiangolo.com/
- Streamlit 문서: https://docs.streamlit.io/
- OpenAI Responses API: https://platform.openai.com/docs/

---

**Last updated:** 2026-07-15