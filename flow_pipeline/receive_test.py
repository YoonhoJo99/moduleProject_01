import logging
from pathlib import Path

from flask import Flask, request
from werkzeug.utils import secure_filename


#pcap 보낼 포트
LISTEN_PORT = 5000

#현재 파일이 들어 있는 flow_pipeline 폴더
BASE_DIR = Path(__file__).resolve().parent

#받은 pcap을 저장할 폴더
RECEIVED_DIR = BASE_DIR / "received"
RECEIVED_DIR.mkdir(exist_ok=True)


#로그 설정
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

log = logging.getLogger(__name__)

#Flask 서버 생성
app = Flask(__name__)


#파일을 보내는 주소
#http://내_Tailscale_IP:5000/upload
@app.route("/upload", methods=["POST"])
def upload():
    uploaded_file = request.files.get("file")

    #file이라는 이름으로 전송된 파일이 없는 경우
    if uploaded_file is None:
        return {"message": "전송된 파일이 없습니다."}, 400

    #파일 이름이 비어 있는 경우
    if uploaded_file.filename == "":
        return {"message": "파일 이름이 없습니다."}, 400

    #위험한 경로 문자를 제거한 안전한 파일 이름
    filename = secure_filename(uploaded_file.filename)

    #pcap 파일인지 확인
    if not filename.lower().endswith((".pcap", ".pcapng")):
        return {
            "message": "pcap 또는 pcapng 파일만 받을 수 있습니다."
        }, 400

    #received 폴더에 저장
    save_path = RECEIVED_DIR / filename
    uploaded_file.save(save_path)

    file_size = save_path.stat().st_size

    log.info(
        "파일 수신 완료: %s (%d bytes)",
        filename,
        file_size,
    )

    return {
        "message": "pcap 파일 수신 완료",
        "filename": filename,
        "size": file_size,
    }, 200


#서버가 작동 중인지 확인하는 주소
@app.route("/health", methods=["GET"])
def health():
    return {
        "status": "ok",
        "service": "pcap-receive-test",
    }, 200


if __name__ == "__main__":
    log.info("수신 테스트 서버 시작: 포트 %d", LISTEN_PORT)

    app.run(
        host="0.0.0.0",
        port=LISTEN_PORT,
        debug=False,
    )