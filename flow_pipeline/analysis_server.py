import logging
import subprocess
import sys
import threading
from pathlib import Path

import requests
from flask import Flask, request
from werkzeug.utils import secure_filename


#pcap을 전송할 포트
LISTEN_PORT = 5000

#AI팀Tailscale IP, 포트, 경로로 나중에 수정
PREDICT_URL = "http://AI팀_TAILSCALE_IP:6000/upload"

#True이면 AI팀 전송 성공 후 중간 파일들을 삭제
DELETE_INTERMEDIATE = False

#CICFlowMeter 명령어
CICFLOWMETER_COMMAND = "cicflowmeter"


#경로설정

#현재 analysis_server.py가 위치한 flow_pipeline 폴더
BASE_DIR = Path(__file__).resolve().parent

#수신한 pcap 저장 폴더
RECEIVED_DIR = BASE_DIR / "received"

#CICFlowMeter가 생성한 원본 CSV 저장 폴더
CONVERTED_DIR = BASE_DIR / "converted"

#CIC-IDS2017 형식으로 정리한 CSV 저장 폴더
NORMALIZED_DIR = BASE_DIR / "normalized"

#CSV 표준화 파일
NORMALIZE_SCRIPT = BASE_DIR / "normalize.py"


#필요한 폴더가 없으면 자동 생성
for directory in (
    RECEIVED_DIR,
    CONVERTED_DIR,
    NORMALIZED_DIR,
):
    directory.mkdir(parents=True, exist_ok=True)



#로그 설정
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            BASE_DIR / "analysis_server.log",
            encoding="utf-8",
        ),
    ],
)

log = logging.getLogger(__name__)


#Flask 서버 생성
app = Flask(__name__)



#1단계: pcap → CICFlowMeter 원본 CSV
def convert_pcap_to_csv(
    pcap_path: Path,
    csv_path: Path,
) -> bool:
    log.info(
        "CICFlowMeter 변환 시작: %s",
        pcap_path.name,
    )

    command = [
        CICFLOWMETER_COMMAND,
        "-f",
        str(pcap_path),
        "-c",
        str(csv_path),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
        )

    except FileNotFoundError:
        log.error(
            "cicflowmeter 명령을 찾을 수 없습니다. "
            "실행 서버에 CICFlowMeter가 설치되어 있는지 확인하세요."
        )
        return False

    except subprocess.TimeoutExpired:
        log.error(
            "CICFlowMeter 변환 시간 초과: %s",
            pcap_path.name,
        )
        return False

    if result.returncode != 0:
        log.error(
            "CICFlowMeter 변환 실패 (%s): %s",
            pcap_path.name,
            result.stderr.strip(),
        )
        return False

    if not csv_path.exists():
        log.error(
            "CICFlowMeter 실행은 끝났지만 CSV가 생성되지 않았습니다: %s",
            csv_path,
        )
        return False

    log.info(
        "CICFlowMeter CSV 생성 완료: %s",
        csv_path.name,
    )

    return True



#2단계: 원본 CSV → CIC-IDS2017 형식 CSV
def normalize_csv(
    raw_csv: Path,
    normalized_csv: Path,
) -> bool:
    log.info(
        "CSV 표준화 시작: %s",
        raw_csv.name,
    )

    command = [
        sys.executable,
        str(NORMALIZE_SCRIPT),
        str(raw_csv),
        str(normalized_csv),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
        )

    except subprocess.TimeoutExpired:
        log.error(
            "CSV 표준화 시간 초과: %s",
            raw_csv.name,
        )
        return False

    if result.returncode != 0:
        log.error(
            "CSV 표준화 실패 (%s): %s",
            raw_csv.name,
            result.stderr.strip(),
        )
        return False

    if not normalized_csv.exists():
        log.error(
            "normalize.py 실행 후 결과 파일이 생성되지 않았습니다: %s",
            normalized_csv,
        )
        return False

    log.info(
        "표준화 CSV 생성 완료: %s",
        normalized_csv.name,
    )

    return True



#3단계: 최종 CSV → AI팀 서버
def send_to_predict_server(
    normalized_csv: Path,
) -> bool:
    log.info(
        "AI팀 서버 전송 시작: %s",
        normalized_csv.name,
    )

    try:
        with normalized_csv.open("rb") as csv_file:
            response = requests.post(
                PREDICT_URL,
                files={
                    "file": (
                        normalized_csv.name,
                        csv_file,
                        "text/csv",
                    )
                },
                timeout=30,
            )

    except requests.RequestException as error:
        log.error(
            "AI팀 서버 연결 실패 (%s): %s",
            normalized_csv.name,
            error,
        )
        return False

    if not response.ok:
        log.error(
            "AI팀 서버 전송 실패: HTTP %s / %s",
            response.status_code,
            response.text.strip(),
        )
        return False

    log.info(
        "AI팀 서버 전송 완료: %s / 응답=%s",
        normalized_csv.name,
        response.text.strip(),
    )

    return True



#pcap 한 개의 전체 처리 과정
def process_pcap(
    pcap_path: Path,
) -> None:
    #cap_20260714.pcap → cap_20260714
    base_name = pcap_path.stem

    #CICFlowMeter 원본 CSV 경로
    raw_csv = CONVERTED_DIR / f"{base_name}.csv"

    #CIC-IDS2017 형식 최종 CSV 경로
    normalized_csv = (
        NORMALIZED_DIR / f"{base_name}.csv"
    )

    log.info(
        "전체 처리 시작: %s",
        pcap_path.name,
    )

    try:
        #pcap → CICFlowMeter CSV
        if not convert_pcap_to_csv(
            pcap_path,
            raw_csv,
        ):
            return

        #원본 CSV → CIC-IDS2017 형식
        if not normalize_csv(
            raw_csv,
            normalized_csv,
        ):
            return

        #최종 CSV → AI팀 서버
        if not send_to_predict_server(
            normalized_csv,
        ):
            return

        #모든 과정이 성공한 경우에만 파일 삭제
        if DELETE_INTERMEDIATE:
            for file_path in (
                pcap_path,
                raw_csv,
                normalized_csv,
            ):
                try:
                    file_path.unlink()
                except OSError:
                    pass

        log.info(
            "전체 처리 완료: %s",
            base_name,
        )

    except Exception as error:
        log.exception(
            "처리 중 예외 발생 (%s): %s",
            base_name,
            error,
        )



# A=> pcap을 보내는 주소
# POST
# http://내_Tailscale_IP:5000/upload
@app.route("/upload", methods=["POST"])
def upload_pcap():
    uploaded_file = request.files.get("file")

    if uploaded_file is None:
        return {
            "message": "file 필드가 없습니다."
        }, 400

    if uploaded_file.filename == "":
        return {
            "message": "파일 이름이 없습니다."
        }, 400

    filename = secure_filename(
        uploaded_file.filename
    )

    if not filename.lower().endswith(
        (".pcap", ".pcapng")
    ):
        return {
            "message": (
                "pcap 또는 pcapng 파일만 "
                "전송할 수 있습니다."
            )
        }, 400

    save_path = RECEIVED_DIR / filename

    #전송된 pcap 저장
    uploaded_file.save(save_path)

    log.info(
        "pcap 수신 완료: %s",
        filename,
    )

    #HTTP 응답은 바로 반환하고,
    #변환 과정은 별도 스레드에서 수행
    threading.Thread(
        target=process_pcap,
        args=(save_path,),
        daemon=True,
    ).start()

    return {
        "message": "pcap 파일 수신 완료",
        "filename": filename,
    }, 200


#서버 상태 확인용 주소
@app.route("/health", methods=["GET"])
def health():
    return {
        "status": "ok",
        "service": "flow-analysis-server",
    }, 200



#서버 실행
if __name__ == "__main__":
    log.info(
        "분석 서버 시작: 0.0.0.0:%d",
        LISTEN_PORT,
    )

    log.info(
        "AI팀 서버 주소: %s",
        PREDICT_URL,
    )

    app.run(
        host="0.0.0.0",
        port=LISTEN_PORT,
        debug=False,
    )