#!/usr/bin/env python3
"""
안정적인 Prowler 분석 MCP 서버 (HTML, CSV, JSON 지원) + IaC YAML Writer
"""

import json
import os
import re
import yaml
import logging
from datetime import datetime
from idlelib.browser import file_open
from pathlib import Path
from typing import List, Annotated

import requests
from fastmcp import FastMCP
import argparse
from parser import *
from pprint import pp
from pydantic import BaseModel, Field, ValidationError

# Configure logging for YAML writer
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# FastMCP 앱 초기화
mcp = FastMCP("Prowler Analyzer with IaC YAML Writer")

# 분석할 output 폴더 경로  
# OUTPUT_DIR = Path(r"C:\Users\김서연\Desktop\whs-compler-mcp\output")
BASEDIR = Path(__file__).resolve().parent.parent
# print(BASEDIR.joinpath("./output"))
OUTPUT_DIR = BASEDIR.joinpath("prowler-reports")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# IaC YAML Writer 설정
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent  # 프로젝트 루트 디렉토리 (src 폴더의 상위)
IAC_OUTPUT_DIR = PROJECT_ROOT.joinpath("IaC_output")

# Create IaC_output directory if it doesn't exist
try:
    IAC_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"IaC_output directory ensured at: {IAC_OUTPUT_DIR}")
except Exception as e:
    logger.critical(f"Failed to create IaC_output directory: {e}")
    raise

_iac_root_path = IAC_OUTPUT_DIR.resolve()
logger.info(f"IaC root directory set to: {_iac_root_path}")

# --- Pydantic Model Definition for YAML Writer ---
class YamlWriteParameters(BaseModel):
    """Parameters for writing a YAML file."""
    path: Annotated[str, Field(description="Path to the YAML file relative to IaC_output directory")]
    content: Annotated[str, Field(description="The YAML content as a string.")]
    create_dirs: Annotated[bool, Field(default=False, description="Whether to create parent directories if they do not exist.")]

# --- Utility Functions for YAML Writer ---
def _is_path_safe(root_path: str, target_path: str) -> bool:
    """
    Checks if the target_path is safely within the root_path.
    Prevents directory traversal attacks.
    """
    if not root_path:
        logger.error("Root path is not set, cannot check path safety.")
        return False
    try:
        abs_root = os.path.abspath(root_path)
        abs_target = os.path.abspath(os.path.join(root_path, target_path))
        is_safe = abs_target.startswith(abs_root)
        logger.debug(f"Path safety check: root='{abs_root}', target='{abs_target}', safe={is_safe}")
        return is_safe
    except Exception as e:
        logger.error(f"Error during path safety check: {e}")
        return False

def set_iac_root_directory(root_dir: str):
    """Set the IaC root directory."""
    global _iac_root_path
    try:
        if not os.path.isdir(root_dir):
            logger.info(f"Creating IaC root directory: {root_dir}")
            os.makedirs(root_dir, exist_ok=True)
        _iac_root_path = os.path.abspath(root_dir)
        logger.info(f"IaC root directory set to: {_iac_root_path}")
    except Exception as e:
        logger.critical(f"Failed to set IaC root directory '{root_dir}': {e}")
        raise

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

# ========== PROWLER ANALYSIS TOOLS ==========

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
def analyze_prowler_results(file_path, file_preview_length:int=500) -> str:
    """Prowler 결과 파일을 분석하고 내용을 표시합니다.
    :param file_path: 분석할 Prowler 결과 파일 경로
    :param file_preview_length: 미리보기 텍스트 길이 (기본값: 500자)
    :return: 분석 결과 문자열
    """
    # """최신 Prowler 결과를 분석하고 내용을 표시합니다."""
    # latest_file, error = get_latest_file()
    # if error:
    #     return f"❌ {error}"
    file_path = Path(file_path)
    try:
        # 파일 읽기
        with open(file_path, 'r', encoding='utf-8') as file:
            file_content = file.read()
        
        # 파일 확장자에 따른 분석
        file_ext = file_path.suffix.lower()

        if file_ext in ['.html', '.htm']:
            # analysis = analyze_html_file(content, latest_file)
            # analysis = parse_prowler_report_html_2(content, latest_file)
            analysis = parse_prowler_report_html(file_content, file_preview_length)
        elif file_ext == '.csv':
            analysis = analyze_csv_file(file_content, file_path)
        elif file_ext in ['.json', '.json-asff']:
            # analysis = analyze_json_file(file_content, file_path)
            analysis = parse_prowler_report_asff_json(file_content)
        else:
            analysis = {
                "file_type": f"텍스트 파일 ({file_ext})",
                "content_length": len(file_content),
                "line_count": len(file_content.splitlines()),
                "preview": file_content[:200] + "..." if len(file_content) > 200 else file_content
            }

        # 오류 체크
        if "error" in analysis:
            return f"❌ 파일 분석 실패: {analysis['error']}"

        # 보고서 생성
        report = f"""
# 🛡️ Prowler 결과 분석

##  파일 정보
• **파일명**: {file_path.name}
• **크기**: {file_path.stat().st_size:,} bytes
• **수정일**: {datetime.fromtimestamp(file_path.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}
• **파일 유형**: {analysis.get('file_type', '알 수 없음')}

##  분석 결과
"""

        # HTML 파일 결과
        if analysis.get("file_type") == "Prowler HTML Report":
            keywords = analysis.get("keyword_counts", {})

            report += \
f"""###  보안 점검 상태 (키워드 기반)
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
def get_security_summary(file_path) -> str:
    """보안 상태 간단 요약을 제공합니다."""
    # latest_file, error = get_latest_file()
    #
    # if error:
    #     return f"❌ {error}"
    file_path = Path(file_path)
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
        
        # 간단한 통계
        pass_count = len(re.findall(r'\bPASS\b', file_content, re.IGNORECASE))
        fail_count = len(re.findall(r'\bFAIL\b', file_content, re.IGNORECASE))
        critical_count = len(re.findall(r'\bCRITICAL\b', file_content, re.IGNORECASE))
        
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

**파일**: {file_path.name}
**분석 시점**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        return summary
        
    except Exception as e:
        return f" 요약 생성 중 오류: {str(e)}"

@mcp.tool()
def get_prowler_reports_list() -> List[tuple]:
    """Prowler 결과 파일 목록을 가져옵니다.
    :param
        None
    :return:
        list[]: Prowler 결과 파일 목록
    """
    try:
        files = [f for f in OUTPUT_DIR.iterdir() if f.is_file()]
        if not files:
            return []

        report_list = []
        for file in sorted(files, key=lambda f: f.stat().st_mtime, reverse=True):
            file_stat = file.stat()
            if file.name == '.DS_Store':
                continue
            report_list.append((file.name, file, f'{round(file_stat.st_size/1024):,} KB', file.suffix))
        return report_list
    except Exception as e:
        return [(f"❌ 파일 목록 가져오기 실패: {str(e)}",)]

@mcp.tool()
def get_file_content(file_path: str) -> str:
    """파일 내용을 가져옵니다.
    :param file_path: 파일 경로
    :return: 파일 내용
    """
    try:
        file_path = Path(file_path)
        if not file_path.exists():
            return f"❌ 파일이 존재하지 않습니다: {file_path}"

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        # 파일 내용이 2MB를 초과하면 미리보기만 제공
        if len(content) > 2 * 1024 * 1024:  # 2MB
            return f"📄 파일 내용이 너무 깁니다. 미리보기:\n{content[:2000]}..."
        return content

    except Exception as e:
        return f"❌ 파일 읽기 실패: {str(e)}"


@mcp.tool()
def get_cloud_custodian_aws_resource_reference_html(resource_name: str) -> str:
    """
    Generate HTML reference for a given AWS resource name.
    :param resource_name: str - Name of the AWS resource ("s3", "iam-role", "iam-user", "security-group", "cloudtrail", "ec2", "rds", "vpc", "lambda", "kms")
    :return: HTML string with the resource reference.
    """
    url = f"https://cloudcustodian.io/docs/aws/resources/{resource_name}.html"
    if resource_name not in {
        "s3", "iam-role", "iam-user", "security-group", "cloudtrail",
        "ec2", "rds", "vpc", "lambda", "kms"
    }:
        return f"{resource_name} is not a valid resource name., please use one of the following: s3, iam-role, iam-user, security-group, cloudtrail, ec2, rds, vpc, lambda, kms."
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching resource reference for {resource_name}: {e}")
        return f"{resource_name.capitalize()} (reference not available)"

# ========== IAC YAML WRITER TOOLS ==========

@mcp.tool()
def write_yaml_file(
    path: Annotated[str, Field(description="Path to the YAML file to write. Must be relative to the IaC_output directory.")],
    content: Annotated[str, Field(description="The YAML content as a string.")],
    create_dirs: Annotated[bool, Field(default=False, description="Whether to create parent directories if they do not exist.")] = False
) -> str:
    """Write YAML content to the specified file in the IaC_output directory."""
    logger.info(f"Writing YAML file: path='{path}', create_dirs={create_dirs}")
    
    # Validate parameters using Pydantic
    try:
        params = YamlWriteParameters(path=path, content=content, create_dirs=create_dirs)
        logger.info(f"Parameters validated: path='{params.path}', create_dirs={params.create_dirs}")
    except ValidationError as e:
        error_msg = f"Invalid parameters for write-yaml-file: {e.errors()}"
        logger.error(error_msg)
        raise ValueError(error_msg)

    # Check path safety
    if not _is_path_safe(str(_iac_root_path), params.path):
        error_msg = f"Unsafe path '{params.path}' outside root directory '{_iac_root_path}'"
        logger.error(error_msg)
        raise ValueError(error_msg)

    full_file_path = _iac_root_path / params.path
    directory = full_file_path.parent
    logger.info(f"Full target path: '{full_file_path}', Directory: '{directory}'")

    try:
        # Create directories if needed
        if params.create_dirs:
            if not directory.exists():
                logger.info(f"Creating parent directories for '{directory}'")
                directory.mkdir(parents=True, exist_ok=True)
            else:
                logger.debug(f"Directory '{directory}' already exists")
        elif not directory.exists():
            error_msg = f"Parent directory '{directory}' does not exist and create_dirs is false"
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Validate YAML content
        try:
            yaml.safe_load(params.content)
            logger.info("YAML content is valid")
        except yaml.YAMLError as e:
            error_msg = f"Invalid YAML content: {e}"
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Write the file
        logger.info(f"Writing to file: '{full_file_path}'")
        with open(full_file_path, 'w', encoding='utf-8') as f:
            f.write(params.content)
        
        success_msg = f"Successfully wrote YAML to '{params.path}' in IaC_output directory: {full_file_path}"
        logger.info(success_msg)
        return success_msg

    except IOError as e:
        error_msg = f"Failed to write file '{params.path}': {e}"
        logger.error(error_msg)
        raise IOError(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error during file operation: {e}"
        logger.critical(error_msg, exc_info=True)
        raise Exception(error_msg)

@mcp.tool()
def create_iac_directory(
    directory_path: Annotated[str, Field(description="Directory path to create relative to IaC_output directory")]
) -> str:
    """Create a directory in the IaC_output folder."""
    logger.info(f"Creating directory: {directory_path}")
    
    # Check path safety
    if not _is_path_safe(str(_iac_root_path), directory_path):
        error_msg = f"Unsafe path '{directory_path}' outside root directory '{_iac_root_path}'"
        logger.error(error_msg)
        return error_msg

    full_dir_path = _iac_root_path / directory_path
    
    try:
        full_dir_path.mkdir(parents=True, exist_ok=True)
        success_msg = f"Successfully created directory: {full_dir_path}"
        logger.info(success_msg)
        return success_msg
    except Exception as e:
        error_msg = f"Failed to create directory '{directory_path}': {e}"
        logger.error(error_msg)
        return error_msg

@mcp.tool()
def list_iac_files() -> str:
    """List all files in the IaC_output directory."""
    try:
        if not _iac_root_path.exists():
            return f"IaC_output directory does not exist: {_iac_root_path}"
        
        files = []
        for item in _iac_root_path.rglob("*"):
            if item.is_file():
                relative_path = item.relative_to(_iac_root_path)
                file_size = item.stat().st_size
                modified_time = datetime.fromtimestamp(item.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                files.append(f"📄 {relative_path} ({file_size:,} bytes, modified: {modified_time})")
        
        if not files:
            return f"No files found in IaC_output directory: {_iac_root_path}"
        
        return f"""
# 📁 IaC Output Directory Contents

**Location**: {_iac_root_path}

## Files:
""" + "\n".join(files)

    except Exception as e:
        error_msg = f"Failed to list IaC files: {e}"
        logger.error(error_msg)
        return error_msg

@mcp.tool()
def get_iac_file_content(
    file_path: Annotated[str, Field(description="Path to the file relative to IaC_output directory")]
) -> str:
    """Get the content of a file in the IaC_output directory."""
    # Check path safety
    if not _is_path_safe(str(_iac_root_path), file_path):
        error_msg = f"Unsafe path '{file_path}' outside root directory '{_iac_root_path}'"
        logger.error(error_msg)
        return error_msg

    full_file_path = _iac_root_path / file_path
    
    try:
        if not full_file_path.exists():
            return f"File does not exist: {file_path}"
        
        if not full_file_path.is_file():
            return f"Path is not a file: {file_path}"
        
        with open(full_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return f"""
# 📄 File Content: {file_path}

**Full Path**: {full_file_path}
**Size**: {len(content):,} characters

## Content:
```yaml
{content}
```
"""
    
    except Exception as e:
        error_msg = f"Failed to read file '{file_path}': {e}"
        logger.error(error_msg)
        return error_msg


if __name__ == "__main__":
    print("Prowler MCP Server with IaC YAML Writer 시작 중...")
    print(f"📊 Prowler 분석 대상 폴더: {OUTPUT_DIR}")
    print(f"📝 IaC YAML 출력 폴더: {IAC_OUTPUT_DIR}")
    args = parse_args()
    if not args.no_mcp_run:
        print("🚀 MCP 서버 실행 중...")
        mcp.run()
    else:
        print("🔧 MCP 서버 실행을 건너뜁니다. (디버깅 모드)")
        with open(get_latest_file()[0], "r", encoding="utf-8") as f:
            pass
            # print(get_prowler_reports_list())