# dvwa dataset

1줄 요약 - raw_merged.csv로 normalize 처리

1. network.pcap
- dvwa dataset 기반 공격 패킷 캡처파일

2. metrics.csv
- 공격 시간 동안 cAdvisor에서 1초마다 수집한 DVWA 컨테이너 CPU 메모리 네트워크 원본 metrics

3. ntl_output.csv
- 확인 결과 dvwa dataset이 cicflowmeter가 아닌 NTLFowLyzer로 pcap을 변환하고 있어 해당 툴 사용하여 flow 형태로 변환

4. raw_merged.csv
- ntl_output.csv와 metrics.csv를 시간 기준으로 병합, 공격 구간에 따라 label을 붙인 파일

5. raw_merged.csv에 dvwa dataset 기반 정상/공격 트래픽 별 label이 붙어있어 예측시에는 label 컬럼을 입력값에서 제외해야합니다
