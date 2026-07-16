# 데이터 설명

1. 현재 CSE_CIC_IDS2018_target_clean.csv 로만 학습하면 학습 모델이 실습 환경을
   잡지 못해 현재 환경 학습용 데이터셋을 만들었습니다.
   (cross-dataset generalization 이라고합니다)

2. 파일설명
   - 머신 학습용 데이터: train_local.csv
   - 머신 테스트 데이터: test_local.csv

3. 트래픽유형
   - 정상트래픽
   - HulkDoS
   - Slowloris
   - SSH Brute-force
   - CES_CIC_IDS2018 기반으로 공격 유형을 선정했고 빠져있는 공격들은 해당
     데이터셋에서도 표본이 너무 적어서 제외했습니다

4. 학습용과 테스트용 차이
   - 정상트래픽: 동일
   - 학습용 HulkDoS: 스레드 강도 20으로 설정
   - 테스트 HulkDoS: 스레드 강도 50으로 설정
   - 학습용 Slowloris: 소켓 300/600으로 설정
   - 테스트 Slowloris: 소켓 900으로 설정
   - 학습용 SSHBF: bruteforce 동시 시도 옵션 4로 설정
   - 테스트 SSHBF: bruteforce 동시 시도 옵션 16으로 설정

5. 데이터구조
   - 기존 학습 데이터셋 CES_CIC ... 의 83개 열 중 62개 피처만 학습에 사용하는
   것으로 확인했습니다.
   - train_local.csv와 test_local.csv는 동일한 62개 피처에 label열만 추가했습니다.
   - 두 파일 모두 정답값 확인을 위해 label 열 추가해두었습니다. 학습 또는 평가 시 label 열은 입력 피처에서 제외하고 정답값으로 분리하여 사용하시면 될 것 같습니다.

6. 하위 directory는 종합 데이터 생성에 쓰인 원본 파일입니다. 혹시 필요하실까 넣어둡니다.