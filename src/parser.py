import os
import sys
import bs4
import json


def parse_prowler_report_html(html_content, preview_length:int=500) -> dict:
    """
    Prowler HTML 리포트 파싱 함수
    :param html_content: HTML 컨텐츠 문자열
    :param preview_length: 미리보기 텍스트 길이
    :return:
    """
    try:
        # BeautifulSoup 파싱
        soup = bs4.BeautifulSoup(html_content, 'html.parser')

        # text_preview (본문 일부)
        text_preview = soup.get_text(separator=' ', strip=True)[:preview_length]

        # 키워드 카운트용 본문 추출
        findings_table = soup.find('table', {'id': 'findingsTable'})
        findings_html = findings_table.decode() if findings_table else html_content

        # 전역 대문자, 소문자 키워드 대응
        keyword_list = ['PASS', 'FAIL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        keyword_counts = {k: 0 for k in keyword_list}
        for row in soup.find_all('tr'):
            cols = row.find_all('td')
            if cols and len(cols) > 1:
                status = cols[0].get_text(strip=True).upper()
                severity = cols[1].get_text(strip=True).upper()
                if status in keyword_counts:
                    keyword_counts[status] += 1
                if severity in keyword_counts:
                    keyword_counts[severity] += 1

        # dict 리턴
        return {
            'file_type': 'Prowler HTML Report',
            # 'file_size': file_size,
            # 'text_length': text_length,
            'keyword_counts': keyword_counts,
            'text_preview': text_preview
        }
    except Exception as e:
        print(f"Error parsing HTML report: {e}", file=sys.stderr)
        return {"error": str(e)}


def parse_prowler_report_asff_json(json_content, preview_length=500) -> dict:
    try:
        # JSON 파싱
        json_data = json.loads(json_content)

        # 키워드 카운트
        keyword_list = ['PASS', 'FAIL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        keyword_counts = {k: 0 for k in keyword_list}
        for finding in json_data:
            # 상태(Compliance.Status)와 심각도(Severity.Label)
            compliance_status = finding.get("Compliance", {}).get("Status", "").upper()
            severity_label = finding.get("Severity", {}).get("Label", "").upper()
            if compliance_status == "PASSED":
                compliance_status = "PASS"
            else:
                compliance_status = "FAIL"
            keyword_counts[compliance_status] += 1
            keyword_counts[severity_label] += 1

        # 미리보기 텍스트
        text_preview = json_content[:preview_length]

        result = {
            'file_type': 'Prowler JSON Report',
            "data_type": type(json_content).__name__,
            # 'file_size': file_size,
            # 'text_length': text_length,
            'keyword_counts': keyword_counts,
            # 'text_preview': text_preview
        }

        if isinstance(json_data, list):
            result["item_count"] = len(json_data)
            if json_data and isinstance(json_data[0], dict):
                result["sample_keys"] = list(json_data[0].keys())[:5]
        elif isinstance(json_data, dict):
            result["keys"] = list(json_data.keys())[:10]

        # 결과 dict
        return result

    except Exception as e:
        print(f"Error parsing ASFF JSON report: {e}")
        return {"error": str(e)}

if __name__ == "__main__":
    report = "../prowler-reports/prowler-report-20250715-011202.asff.json"
    with open(report, 'r', encoding='utf-8') as f:
        content = f.read()
    r = parse_prowler_report_asff_json(content)
    print(r)
