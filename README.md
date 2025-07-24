# Prowler MCP Server for Claude Desktop by Compler
This is an MCP server that analyzes Prowler security scan results.

## Features
-`get_latest_prowler_file`: Retrieve latest file information
-`analyze_prowler_results`: Detailed security analysis (now supports a file_preview_length parameter for controlling text preview length)
-`get_security_summary`: Security status summary
-`get_prowler_reports_list`: Retrieve a list of Prowler report files.
-`get_file_content`: Retrieve the content of a specified file.

## Structure
```
compler-mcp-claude_desktop/
├── src/
│   └── prowler_mcp_server.py     # Main MCP server
├── config/
│   └── claude_desktop_config.json # Claude Desktop settings >> Due to config conflict, using fastmcp's own functionality. (fastmcp install claude-desktop src\prowler_mcp_server.py:mcp)
├── logs/                         # Log files
├── requirements.txt              # Python dependencies
├── run.bat                       # Execution script
└── README.md                     # This file
```

## Installation and Execution
### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Claude Desktop Configuration
Copy `config/claude_desktop_config.json` content to Claude Desktop settings:
```
%APPDATA%\Claude\claude_desktop_config.json
```

#### claude_desktop_config.json
```
{
  "mcpServers": {
    "Prowler Analyzer": {
      "command": "{uv-path}/uv",
      "args": [
        "run",
        "--with",
        "fastmcp",
        "--with",
        "beautifulsoup4",
        "--with",
        "requests",
        "fastmcp",
        "run",
        "{project-path}/src/prowler_mcp_server.py:mcp"
      ],
      "env": {},
      "transport": "stdio"
    }
  }
}
```

### 3. Test Execution
# Direct execution
```bash
python src\prowler_mcp_server.py

# Or execute with batch file

run.bat
```

### 4. Restart Claude Desktop
Completely close and restart Claude Desktop


## Analysis Target
Path: `./prowler-reports` (This directory is automatically created relative to the project root.)

Supported Formats: HTML, CSV, JSON, JSON-ASFF, and general text files.

Prowler ASFF results specialized analysis

## References (Additional needed)
-[Prowler Official Documentation](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app/)
-[KISA-ISMS-P Compliance](https://hub.prowler.com/compliance/kisa_isms_p_2023_aws)

## Support
```
ye11oc4t@gmail.com or Discord re-tired
woohyun212@gmail.com or Discord a_b_normal
```


___



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

#### claude_desktop_config.json
```
{
  "mcpServers": {
    "Prowler Analyzer": {
      "command": "{uv-path}/uv",
      "args": [
        "run",
        "--with",
        "fastmcp",
        "--with",
        "beautifulsoup4",
        "--with",
        "requests",
        "fastmcp",
        "run",
        "{project-path}/src/prowler_mcp_server.py:mcp"
      ],
      "env": {},
      "transport": "stdio"
    }
  }
}
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
- 경로: `./prowler-reports` (이 디렉토리는 프로젝트 루트를 기준으로 자동으로 생성됩니다.) 
- 지원 형식: HTML, CSV, JSON, JSON-ASFF, 텍스트 파일
- Prowler ASFF 결과 특화 분석

## 참고 자료 (추가 필요)
- [Prowler 공식 문서](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app/)
- [KISA-ISMS-P 컴플라이언스](https://hub.prowler.com/compliance/kisa_isms_p_2023_aws)

## 지원
```
ye11oc4t@gmail.com or Discord re-tired
woohyun212@gmail.com or Discord a_b_normal
```
