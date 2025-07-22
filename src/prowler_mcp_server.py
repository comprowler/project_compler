#!/usr/bin/env python3
"""
안정적인 Prowler 분석 MCP 서버 (HTML, CSV, JSON 지원)
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from fastmcp import FastMCP
import argparse
from parser import *
from pprint import pp

# FastMCP 앱 초기화
mcp = FastMCP("Prowler Analyzer")

# 분석할 output 폴더 경로  
# OUTPUT_DIR = Path(r"C:\Users\김서연\Desktop\whs-compler-mcp\output")
BASEDIR = Path(__file__).resolve().parent.parent
# print(BASEDIR.joinpath("./output"))
OUTPUT_DIR = BASEDIR.joinpath("prowler-reports")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def parse_args():
    """명령줄 인자 파싱"""
    global OUTPUT_DIR
    p = argparse.ArgumentParser(description="Prowler MCP 서버 설정")
    p.add_argument(
        "--output-dir",
        type=str,
        default=str(OUTPUT_DIR),
        help="분석할 Prowler 결과 파일이 있는 디렉토리 경로 (기본값: ./output)",
    )

    p.add_argument(
        "--no-mcp-run",
        type=bool,
        default=False,
        help="MCP 서버를 실행하지 않습니다. (디버깅용)",
    )

    args = p.parse_args()

    # OUTPUT_DIR 업데이트
    OUTPUT_DIR = Path(args.output_dir)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return args

def get_latest_file():
    """최신 파일 찾기"""
    if not OUTPUT_DIR.exists():
        return None, f"Output 디렉토리가 존재하지 않습니다: {OUTPUT_DIR}"
    
    files = {f for f in OUTPUT_DIR.iterdir() if f.is_file()}
    files.discard(Path(OUTPUT_DIR).joinpath('.DS_Store'))
    if not files:
        return None, f"파일이 없습니다: {OUTPUT_DIR}"
    
    latest = max(files, key=lambda f: f.stat().st_mtime)
    return latest, None

def analyze_html_file(content, file_path):
    """HTML 파일 분석 (안전한 버전)"""
    try:
        # HTML 태그 제거
        text_content = re.sub(r'<[^>]+>', '', content)
        text_content = re.sub(r'\s+', ' ', text_content).strip()
        
        # 기본 정보
        result = {

            "file_size": len(content),
            "text_length": len(text_content),
        }
        
        # 간단한 키워드 검색
        keywords = {
            "PASS": len(re.findall(r'\bPASS\b', text_content, re.IGNORECASE)),
            "FAIL": len(re.findall(r'\bFAIL\b', text_content, re.IGNORECASE)),
            "CRITICAL": len(re.findall(r'\bCRITICAL\b', text_content, re.IGNORECASE)),
            "HIGH": len(re.findall(r'\bHIGH\b', text_content, re.IGNORECASE)),
            "MEDIUM": len(re.findall(r'\bMEDIUM\b', text_content, re.IGNORECASE)),
            "LOW": len(re.findall(r'\bLOW\b', text_content, re.IGNORECASE))
        }
        
        result["keyword_counts"] = keywords
        result["text_preview"] = text_content[:300] + "..." if len(text_content) > 300 else text_content
        
        return result
        
    except Exception as e:
        return {"error": f"HTML 분석 오류: {str(e)}"}

def analyze_csv_file(content, file_path):
    """CSV 파일 분석 (안전한 버전)"""
    try:
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        if not lines:
            return {"error": "빈 CSV 파일"}
        
        result = {
            "file_type": "Prowler CSV Results",
            "total_lines": len(lines),
            "header": lines[0] if lines else "",
            "data_rows": len(lines) - 1 if len(lines) > 1 else 0
        }
        
        # 샘플 데이터
        if len(lines) > 1:
            result["sample_rows"] = lines[1:4]  # 처음 3개 데이터 행
        
        return result
        
    except Exception as e:
        return {"error": f"CSV 분석 오류: {str(e)}"}

def analyze_json_file(content, file_path):
    """JSON 파일 분석 (안전한 버전)"""
    try:
        data = json.loads(content)
        
        result = {
            "file_type": "JSON Data",
            "data_type": type(data).__name__
        }
        
        if isinstance(data, list):
            result["item_count"] = len(data)
            if data and isinstance(data[0], dict):
                result["sample_keys"] = list(data[0].keys())[:5]
        elif isinstance(data, dict):
            result["keys"] = list(data.keys())[:10]
        
        return result
        
    except json.JSONDecodeError as e:
        return {"error": f"JSON 파싱 오류: {str(e)}"}
    except Exception as e:
        return {"error": f"JSON 분석 오류: {str(e)}"}

@mcp.tool()
def get_latest_prowler_file() -> str:
    """output 폴더에서 가장 최신 파일 정보를 가져옵니다."""
    latest_file, error = get_latest_file()
    
    if error:
        return f"❌ {error}"
    
    file_stat = latest_file.stat()
    result = f"""
 **최신 Prowler 결과 파일**

• **파일명**: {latest_file.name}
• **전체 경로**: {latest_file}
• **파일 크기**: {file_stat.st_size:,} bytes
• **수정 일시**: {datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}
• **파일 확장자**: {latest_file.suffix}

 **선택 근거**: 이 파일이 {OUTPUT_DIR} 폴더에서 가장 최근에 수정된 파일로, 최신 보안 점검 결과를 포함하고 있습니다.
"""
    return result

@mcp.tool()
def analyze_prowler_results() -> str:
    """최신 Prowler 결과를 분석하고 내용을 표시합니다."""
    latest_file, error = get_latest_file()

    if error:
        return f"❌ {error}"
    
    try:
        content = ""  # 초기화
        # 파일 읽기
        with open(latest_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 파일 확장자에 따른 분석
        file_ext = latest_file.suffix.lower()

        if file_ext in ['.html', '.htm']:
            # analysis = analyze_html_file(content, latest_file)
            # analysis = parse_prowler_report_html_2(content, latest_file)
            analysis = parse_prowler_report_html(content, latest_file)
        elif file_ext == '.csv':
            analysis = analyze_csv_file(content, latest_file)
        elif file_ext in ['.json', '.json-asff']:
            analysis = analyze_json_file(content, latest_file)
            analysis = parse_prowler_report_asff_json(content)
        else:
            analysis = {
                "file_type": f"텍스트 파일 ({file_ext})",
                "content_length": len(content),
                "line_count": len(content.splitlines()),
                "preview": content[:200] + "..." if len(content) > 200 else content
            }

        # 오류 체크
        if "error" in analysis:
            return f"❌ 파일 분석 실패: {analysis['error']}"

        # 보고서 생성
        report = f"""
# 🛡️ Prowler 결과 분석

##  파일 정보
• **파일명**: {latest_file.name}
• **크기**: {latest_file.stat().st_size:,} bytes
• **수정일**: {datetime.fromtimestamp(latest_file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}
• **파일 유형**: {analysis.get('file_type', '알 수 없음')}

##  분석 결과
"""

        # HTML 파일 결과
        if analysis.get("file_type") == "Prowler HTML Report":
            keywords = analysis.get("keyword_counts", {})

            report += f"""
###  보안 점검 상태 (키워드 기반)
• ✅ **PASS**: {keywords.get('PASS', 0)}개 발견
• ❌ **FAIL**: {keywords.get('FAIL', 0)}개 발견

### 🚨 심각도 분포
• 🔴 **CRITICAL**: {keywords.get('CRITICAL', 0)}개 언급
• 🟠 **HIGH**: {keywords.get('HIGH', 0)}개 언급  
• 🟡 **MEDIUM**: {keywords.get('MEDIUM', 0)}개 언급
• 🟢 **LOW**: {keywords.get('LOW', 0)}개 언급

###  보고서 내용 미리보기
```
{analysis.get('text_preview', '내용 없음')}
```
"""

        # CSV 파일 결과
        elif analysis.get("file_type") == "Prowler CSV Results":
            report += f"""
###  CSV 데이터 정보
• **총 라인 수**: {analysis.get('total_lines', 0)}개
• **데이터 행 수**: {analysis.get('data_rows', 0)}개
• **헤더**: {analysis.get('header', '없음')[:100]}...

###  샘플 데이터
"""
            sample_rows = analysis.get('sample_rows', [])
            for i, row in enumerate(sample_rows, 1):
                report += f"{i}. {row[:100]}{'...' if len(row) > 100 else ''}\n"

        # JSON 파일 결과
        elif "JSON" in analysis.get("file_type", ""):
            report += f"""
###  JSON 데이터 정보
• **데이터 타입**: {analysis.get('data_type', '알 수 없음')}
• **항목 수**: {analysis.get('item_count', 'N/A')}
• **주요 키**: {', '.join(analysis.get('sample_keys', []))}
• **점검 상태**: {analysis.get('keyword_counts', {})}
"""

        # 기타 파일
        else:
            report += f"""
###  파일 정보
• **내용 길이**: {analysis.get('content_length', 0)}자
• **라인 수**: {analysis.get('line_count', 0)}개

###  내용 미리보기
```
{analysis.get('preview', '내용 없음')}
```
"""

        # 참고 자료
        report += """
##  보안 분석 참고 자료
• [Prowler 공식 문서](https://docs.prowler.com/)
• [KISA-ISMS-P 컴플라이언스](https://hub.prowler.com/compliance/kisa_isms_p_2023_aws)
• [AWS 보안 모범 사례](https://aws.amazon.com/security/security-resources/)

##  권장사항
1. **실패 항목 우선 검토**: FAIL 상태인 항목들을 우선적으로 해결
2. **심각도별 대응**: CRITICAL > HIGH > MEDIUM > LOW 순서로 처리
3. **정기적 점검**: 월 1회 이상 보안 점검 실시
4. **문서화**: 해결된 항목들에 대한 기록 유지
"""

        return report

    except Exception as e:
        return f"❌ 파일 분석 중 오류 발생: {str(e)}"

@mcp.tool()
def get_security_summary() -> str:
    """보안 상태 간단 요약을 제공합니다."""
    latest_file, error = get_latest_file()
    
    if error:
        return f"❌ {error}"
    
    try:
        with open(latest_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 간단한 통계
        pass_count = len(re.findall(r'\bPASS\b', content, re.IGNORECASE))
        fail_count = len(re.findall(r'\bFAIL\b', content, re.IGNORECASE))
        critical_count = len(re.findall(r'\bCRITICAL\b', content, re.IGNORECASE))
        
        total_checks = pass_count + fail_count
        pass_rate = (pass_count / total_checks * 100) if total_checks > 0 else 0
        
        # 등급 산정
        if pass_rate >= 90:
            grade = "🟢 우수 (A등급)"
        elif pass_rate >= 80:
            grade = "🟡 양호 (B등급)"
        elif pass_rate >= 70:
            grade = "🟠 보통 (C등급)"
        else:
            grade = "🔴 개선 필요 (D등급)"
        
        summary = f"""
#  보안 상태 요약

##  전체 평가
**{grade}**

##  핵심 지표
• **통과율**: {pass_rate:.1f}%
• **통과 항목**: {pass_count}개
• **실패 항목**: {fail_count}개
• **치명적 이슈**: {critical_count}개

##  즉시 조치사항
{"🔴 치명적 이슈가 발견되었습니다. 즉시 확인 필요!" if critical_count > 0 else "✅ 치명적 이슈가 발견되지 않았습니다."}

##  개선 방향
• 현재 통과율 {pass_rate:.1f}%에서 90% 이상 목표
• 실패한 {fail_count}개 항목에 대한 단계적 개선
• 정기적인 보안 점검으로 지속 관리

**파일**: {latest_file.name}
**분석 시점**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        return summary
        
    except Exception as e:
        return f" 요약 생성 중 오류: {str(e)}"

if __name__ == "__main__":
    print(" 안정적인 Prowler MCP Server 시작 중...")
    print(f" 분석 대상 폴더: {OUTPUT_DIR}")
    args = parse_args()
    if not args.no_mcp_run:
        print(" MCP 서버 실행 중...")
        mcp.run()
    else:
        print(" MCP 서버 실행을 건너뜁니다. (디버깅 모드)")
        with open(get_latest_file()[0], "r", encoding="utf-8") as f:
            # pp(analyze_html_file(f.read(), get_latest_file()[0]))
            # pp(parse_prowler_report_html(f.read()), indent=2, width=250)
            # pp(parse_prowler_report_html_2(f.read(), ), indent=2, width=250)
            # print(parse_prowler_report_asff_json(f.read()))
            # pp(analyze_json_file(f.read(), get_latest_file()[0]))
            # print(analyze_prowler_results())
            pass