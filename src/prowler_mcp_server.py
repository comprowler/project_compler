#!/usr/bin/env python3
"""
Stable Prowler Analysis MCP Server (Supports HTML, CSV, JSON)
"""

import json
import os
import re
from datetime import datetime
from idlelib.browser import file_open
from pathlib import Path
from typing import List

from fastmcp import FastMCP
import argparse
from parser import *
from pprint import pp

# FastMCP app initialization
mcp = FastMCP("Prowler Analyzer")

# Path of output folder to analyze
# OUTPUT_DIR = Path(r"C:\Users\김서연\Desktop\whs-compler-mcp\output")
BASEDIR = Path(__file__).resolve().parent.parent
# print(BASEDIR.joinpath("./output"))
OUTPUT_DIR = BASEDIR.joinpath("prowler-reports")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def parse_args():
    """Parse command-line arguments"""
    global OUTPUT_DIR
    p = argparse.ArgumentParser(description="Prowler MCP Server Settings")
    p.add_argument(
        "--output-dir",
        type=str,
        default=str(OUTPUT_DIR),
        help="Directory path containing Prowler result files (default: ./output)",
    )

    p.add_argument(
        "--no-mcp-run",
        type=bool,
        default=False,
        help="Do not run MCP server (for debugging)",
    )

    args = p.parse_args()

    # Update OUTPUT_DIR
    OUTPUT_DIR = Path(args.output_dir)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return args

def get_latest_file():
    """Find the latest file"""
    if not OUTPUT_DIR.exists():
        return None, f"Output directory does not exist: {OUTPUT_DIR}"

    files = {f for f in OUTPUT_DIR.iterdir() if f.is_file()}
    files.discard(Path(OUTPUT_DIR).joinpath('.DS_Store'))
    if not files:
        return None, f"No files found: {OUTPUT_DIR}"

    latest = max(files, key=lambda f: f.stat().st_mtime)
    return latest, None

def analyze_html_file(content, file_path):
    """Analyze HTML file (safe version)"""
    try:
        # Basic information
        # Remove HTML tags
        text_content = re.sub(r'<[^>]+>', '', content)
        text_content = re.sub(r'\s+', ' ', text_content).strip()

        # Basic information
        result = {

            "file_size": len(content),
            "text_length": len(text_content),
        }

        # Simple keyword search
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
        return {"error": f"HTML analysis error: {str(e)}"}

def analyze_csv_file(content, file_path):
    """Analyze CSV file (safe version)"""
    try:
        lines = [line.strip() for line in content.split('\n') if line.strip()]

        if not lines:
            return {"error": "Empty CSV file"}

        result = {
            "file_type": "Prowler CSV Results",
            "total_lines": len(lines),
            "header": lines[0] if lines else "",
            "data_rows": len(lines) - 1 if len(lines) > 1 else 0
        }

        # Sample data
        if len(lines) > 1:
            result["sample_rows"] = lines[1:4]  # first 3 data rows

        return result

    except Exception as e:
        return {"error": f"CSV analysis error: {str(e)}"}

def analyze_json_file(content, file_path):
    """Analyze JSON file (safe version)"""
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
        return {"error": f"JSON parsing error: {str(e)}"}
    except Exception as e:
        return {"error": f"JSON analysis error: {str(e)}"}

@mcp.tool()
def get_latest_prowler_file() -> str:
    """Get the most recent file from output folder."""
    latest_file, error = get_latest_file()

    if error:
        return f"❌ {error}"

    file_stat = latest_file.stat()
    result = f"""
 **Latest Prowler Result File**

• **Filename**: {latest_file.name}
• **Full Path**: {latest_file}
• **File Size**: {file_stat.st_size:,} bytes
• **Modified Date**: {datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}
• **File Extension**: {latest_file.suffix}

 **Selection Reason**: This file is the most recently modified file in the {OUTPUT_DIR} folder, containing the latest security scan results.
"""
    return result

@mcp.tool()
def analyze_prowler_results(file_path, file_preview_length:int=500) -> str:
    """Analyze Prowler result file and display content.
    :param file_path: Path of Prowler result file to analyze
    :param file_preview_length: Preview text length (default: 500 chars)
    :return: Analysis result string
    """
    # """Analyze latest Prowler result and display content."""
    # latest_file, error = get_latest_file()
    # if error:
    #     return f"❌ {error}"
    file_path = Path(file_path)
    try:
        # Read file
        with open(file_path, 'r', encoding='utf-8') as file:
            file_content = file.read()

        # Analyze based on file extension
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
                "file_type": f"Text file ({file_ext})",
                "content_length": len(file_content),
                "line_count": len(file_content.splitlines()),
                "preview": file_content[:200] + "..." if len(file_content) > 200 else file_content
            }

        # Check for errors
        if "error" in analysis:
            return f"❌ File analysis failed: {analysis['error']}"

        # Create report
        report = f"""
# Prowler Result Analysis

##  File Information
• **Filename**: {file_path.name}
• **Size**: {file_path.stat().st_size:,} bytes
• **Modified Date**: {datetime.fromtimestamp(file_path.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}
• **File Type**: {analysis.get('file_type', 'Unknown')}

##  Analysis Results
"""

        # HTML file results
        if analysis.get("file_type") == "Prowler HTML Report":
            keywords = analysis.get("keyword_counts", {})

            report += \
f"""###  Security Check Status (Keyword-based)
• ✅ **PASS**: {keywords.get('PASS', 0)} found
• ❌ **FAIL**: {keywords.get('FAIL', 0)} found

### 🚨 Severity Distribution
• 🔴 **CRITICAL**: {keywords.get('CRITICAL', 0)} mentions
• 🟠 **HIGH**: {keywords.get('HIGH', 0)} mentions  
• 🟡 **MEDIUM**: {keywords.get('MEDIUM', 0)} mentions
• 🟢 **LOW**: {keywords.get('LOW', 0)} mentions

###  Report Content Preview
```
{analysis.get('text_preview', 'No content')}
```
"""

        # CSV file results
        elif analysis.get("file_type") == "Prowler CSV Results":
            report += f"""
###  CSV Data Information
• **Total Lines**: {analysis.get('total_lines', 0)}
• **Data Rows**: {analysis.get('data_rows', 0)}
• **Header**: {analysis.get('header', 'None')[:100]}...

###  Sample Data
"""
            sample_rows = analysis.get('sample_rows', [])
            for i, row in enumerate(sample_rows, 1):
                report += f"{i}. {row[:100]}{'...' if len(row) > 100 else ''}\n"

        # JSON file results
        elif "JSON" in analysis.get("file_type", ""):
            report += f"""
###  JSON Data Information
• **Data Type**: {analysis.get('data_type', 'Unknown')}
• **Item Count**: {analysis.get('item_count', 'N/A')}
• **Key Samples**: {', '.join(analysis.get('sample_keys', []))}
• **Check Status**: {analysis.get('keyword_counts', {})}
"""

        # Other files
        else:
            report += f"""
###  File Information
• **Content Length**: {analysis.get('content_length', 0)} chars
• **Line Count**: {analysis.get('line_count', 0)}

###  Content Preview
```
{analysis.get('preview', 'No content')}
```
"""

        # References
        report += """
##  Security Analysis References
• [Prowler Official Documentation](https://docs.prowler.com/)
• [KISA-ISMS-P Compliance](https://hub.prowler.com/compliance/kisa_isms_p_2023_aws)
• [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)

##  Recommendations
1. **Prioritize failed items**: Address FAIL items first
2. **Severity-based response**: Handle CRITICAL > HIGH > MEDIUM > LOW in order
3. **Regular checks**: Conduct security scans at least monthly
4. **Documentation**: Keep records of resolved items
"""

        return report

    except Exception as e:
        return f"❌ Error during file analysis: {str(e)}"

@mcp.tool()
def get_security_summary(file_path) -> str:
    """Provides a brief security summary."""
    file_path = Path(file_path)
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            file_content = f.read()

        # Simple statistics
        pass_count = len(re.findall(r'\bPASS\b', file_content, re.IGNORECASE))
        fail_count = len(re.findall(r'\bFAIL\b', file_content, re.IGNORECASE))
        critical_count = len(re.findall(r'\bCRITICAL\b', file_content, re.IGNORECASE))

        total_checks = pass_count + fail_count
        pass_rate = (pass_count / total_checks * 100) if total_checks > 0 else 0

        # Grade evaluation
        if pass_rate >= 90:
            grade = "🟢 Excellent (Grade A)"
        elif pass_rate >= 80:
            grade = "🟡 Good (Grade B)"
        elif pass_rate >= 70:
            grade = "🟠 Average (Grade C)"
        else:
            grade = "🔴 Needs Improvement (Grade D)"

        summary = f"""
#  Security Status Summary

##  Overall Evaluation
**{grade}**

##  Key Metrics
• **Pass Rate**: {pass_rate:.1f}%
• **Passed Items**: {pass_count}
• **Failed Items**: {fail_count}
• **Critical Issues**: {critical_count}

##  Immediate Actions
{"🔴 Critical issues detected. Immediate attention required!" if critical_count > 0 else "✅ No critical issues detected."}

##  Improvement Directions
• Aim for pass rate above 90%
• Gradual improvement on {fail_count} failed items
• Continuous management through regular security checks

**File**: {file_path.name}
**Analysis Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

        return summary

    except Exception as e:
        return f" Error generating summary: {str(e)}"

@mcp.tool()
def get_prowler_reports_list() -> List[tuple]:
    """Retrieve list of Prowler result files."""
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
        return [(f"❌ Failed to retrieve file list: {str(e)}",)]

@mcp.tool()
def get_file_content(file_path: str) -> str:
    """Retrieve file content."""
    try:
        file_path = Path(file_path)
        if not file_path.exists():
            return f"❌ File does not exist: {file_path}"

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        # If file content exceeds 2MB, provide preview only
        if len(content) > 2 * 1024 * 1024:  # 2MB
            return f"📄 File content is too large. Preview:\n{content[:2000]}..."
        return content

    except Exception as e:
        return f"❌ Failed to read file: {str(e)}"

if __name__ == "__main__":
    print("Starting Stable Prowler MCP Server...")
    print(f"Target analysis folder: {OUTPUT_DIR}")
    args = parse_args()
    if not args.no_mcp_run:
        print("Running MCP server...")
        mcp.run()
    else:
        print("Skipping MCP server execution. (Debug mode)")
        with open(get_latest_file()[0], "r", encoding="utf-8") as f:
            pass
            # print(get_prowler_reports_list())
