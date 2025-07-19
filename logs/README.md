# Prowler MCP Server for Claude Desktop by Compler

Prowler 보안 점검 결과를 분석하는 MCP 서버입니다.

## 기능
- `get_latest_prowler_file`: 최신 파일 정보 조회
- `analyze_prowler_results`: 상세 보안 분석
- `get_security_summary`: 보안 상태 요약

## 구조
```
compler-mcp-claude_desktop/
├── src/
│   └── prowler_mcp_server.py    # 메인 MCP 서버
├── config/
│   └── claude_desktop_config.json # Claude Desktop 설정  >> config 충돌로 인해 fastmcp 자체 기능 사용중. (fastmcp install claude-desktop src\prowler_mcp_server.py:mcp)
├── logs/                        # 로그 파일들
├── requirements.txt             # Python 의존성
├── run.bat                      # 실행 스크립트
└── README.md                    # 이 파일
```

## 설치 및 실행

### 1. 의존성 설치
```bash
pip install -r requirements.txt
```

### 2. Claude Desktop 설정
`config/claude_desktop_config.json` 내용을 Claude Desktop 설정에 복사:
```
%APPDATA%\Claude\claude_desktop_config.json
```

### 3. 테스트 실행
```bash
# 직접 실행
python src\prowler_mcp_server.py

# 또는 배치 파일로 실행
run.bat
```

### 4. Claude Desktop 재시작
Claude Desktop을 완전히 종료하고 다시 시작

##  분석 대상
- 경로: `C:\Users\김서연\Desktop\whs-compler-mcp\output`
- 지원 형식: JSON, JSON-ASFF, 텍스트 파일
- Prowler ASFF 결과 특화 분석

## 참고 자료 (추가 필요)
- [Prowler 공식 문서](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app/)
- [KISA-ISMS-P 컴플라이언스](https://hub.prowler.com/compliance/kisa_isms_p_2023_aws)

## 지원
ye11oc4t@gmail.com 
or Discord re-tired

>>2025.07.20 기준 필요한 기능: html, json_asff 파일 파싱(Claude가 바로 읽지 못함)