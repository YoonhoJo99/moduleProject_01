import sys
from pathlib import Path

import numpy as np
import pandas as pd


#CSE-CIC-IDS2018 학습에 사용할 62개 열
CICIDS2018_COLUMNS = [
    'dst_port', 'protocol', 'flow_duration', 'flow_byts_s', 
    'flow_pkts_s', 'fwd_pkts_s', 'bwd_pkts_s', 'tot_fwd_pkts', 
    'tot_bwd_pkts', 'totlen_fwd_pkts', 'totlen_bwd_pkts', 
    'fwd_pkt_len_max', 'fwd_pkt_len_min', 'fwd_pkt_len_mean', 
    'fwd_pkt_len_std', 'bwd_pkt_len_max', 'bwd_pkt_len_min', 
    'bwd_pkt_len_mean', 'bwd_pkt_len_std', 'pkt_len_max', 
    'pkt_len_min', 'pkt_len_mean', 'pkt_len_std', 
    'pkt_len_var', 'fwd_header_len', 'bwd_header_len', 
    'fwd_seg_size_min', 'fwd_act_data_pkts', 'flow_iat_mean', 
    'flow_iat_max', 'flow_iat_min', 'flow_iat_std', 'fwd_iat_tot', 
    'fwd_iat_max', 'fwd_iat_min', 'fwd_iat_mean', 'fwd_iat_std', 
    'bwd_iat_tot', 'bwd_iat_max', 'bwd_iat_min', 'bwd_iat_mean', 
    'bwd_iat_std', 'fwd_psh_flags', 'fwd_urg_flags', 'fin_flag_cnt', 
    'syn_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt', 
    'urg_flag_cnt', 'ece_flag_cnt', 'down_up_ratio', 'pkt_size_avg', 
    'init_fwd_win_byts', 'init_bwd_win_byts', 'fwd_seg_size_avg', 
    'bwd_seg_size_avg', 'cwe_flag_count', 'subflow_fwd_pkts', 
    'subflow_bwd_pkts', 'subflow_fwd_byts', 'subflow_bwd_byts'
    ]


#Python cicflowmeter와 CSE-CIC-IDS2018의 컬럼명 차이
COLUMN_MAP = {
    "cwr_flag_count": "cwe_flag_count",
}


#Python cicflowmeter는 시간 피처를 초 단위로 출력하고,
#CSE-CIC-IDS2018 학습 데이터는 마이크로초 단위를 사용하므로 변환
TIME_COLUMNS = [
    "flow_duration",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_tot",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "bwd_iat_tot",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bwd_iat_min",
]


def normalize_csv(input_csv: str, output_csv: str) -> bool:
    input_path = Path(input_csv)
    output_path = Path(output_csv)

    if not input_path.exists():
        print(f"입력 CSV를 찾을 수 없습니다: {input_path}")
        return False

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    #Python cicflowmeter CSV 읽기
    df = pd.read_csv(input_path)
    original_rows = len(df)

    #컬럼명 앞뒤 공백 제거
    df.columns = df.columns.astype(str).str.strip()

    #컬럼명 차이 보정
    df = df.rename(columns=COLUMN_MAP)

    #필요한 62개 열이 모두 있는지 확인
    missing = [
        column
        for column in CICIDS2018_COLUMNS
        if column not in df.columns
    ]

    if missing:
        print("누락된 열:")

        for column in missing:
            print("-", column)

        return False

    #학습에 쓰는 피처를 숫자형으로 변환
    for column in CICIDS2018_COLUMNS:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce",
        )

    #시간 피처를 초 단위에서 마이크로초 단위로 변환
    for column in TIME_COLUMNS:
        df[column] = df[column] * 1_000_000

    #AI팀 학습 피처와 같은 62개 열 및 순서로 선택
    df = df[CICIDS2018_COLUMNS].copy()

    #무한대 값을 결측값으로 변경
    df = df.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    before_clean = len(df)

    #결측값이 포함된 행 제거
    df = df.dropna().reset_index(drop=True)

    #최종 CSV 저장
    df.to_csv(
        output_path,
        index=False,
        encoding="utf-8-sig",
    )

    print("CSE-CIC-IDS2018 형식 변환 완료")
    print("원본 행:", original_rows)
    print("숫자 변환 전 행:", before_clean)
    print("최종 행:", len(df))
    print("최종 열:", len(df.columns))
    print("출력:", output_path)

    return True


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(
            "사용법: python normalize.py "
            "<raw.csv> <normalized.csv>"
        )
        sys.exit(1)

    if not normalize_csv(
        sys.argv[1],
        sys.argv[2],
    ):
        sys.exit(1)
