import os
import bs4


def parse_prowler_report_html(html_content, preview_length=500) -> dict:
    try:
        # 파일 읽기 및 크기
        # with open(file_path, 'r', encoding='utf-8') as f:
        #     html_content = f.read()
        # file_size = os.path.getsize(file_path)
        # text_length = len(html_content)

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
        print(f"Error parsing HTML report: {e}")
        return {"error": str(e)}


