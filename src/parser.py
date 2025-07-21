import os
import bs4

def parse_prowler_result_html(html_content: str) -> dict:
    try:
        soup = bs4.BeautifulSoup(html_content, 'html.parser')
        #
        # # Summary 정보 추출
        # summary = {}
        # summary_card = soup.find('div', class_='card')
        # if summary_card:
        #     items = summary_card.find_all('li', class_='list-group-item')
        #     for item in items:
        #         text = item.get_text(strip=True)
        #         if 'Version:' in text:
        #             summary['version'] = text.split('Version:')[-1].strip()
        #         if 'Date:' in text:
        #             summary['date'] = text.split('Date:')[-1].strip()
        #         if 'Parameters used:' in text:
        #             summary['parameters'] = text.split('Parameters used:')[-1].strip()
        #
        # # AWS Assessment Summary
        # aws_summary = {}
        # for card in soup.find_all('div', class_='card'):
        #     header = card.find('div', class_='card-header')
        #     if not header: continue
        #     title = header.get_text(strip=True)
        #     if title == 'AWS Assessment Summary':
        #         items = card.find_all('li', class_='list-group-item')
        #         for item in items:
        #             text = item.get_text(strip=True)
        #             if 'AWS Account:' in text:
        #                 aws_summary['account'] = text.split('AWS Account:')[-1].strip()
        #             if 'AWS-CLI Profile:' in text:
        #                 aws_summary['profile'] = text.split('AWS-CLI Profile:')[-1].strip()
        #             if 'Audited Regions:' in text:
        #                 aws_summary['regions'] = text.split('Audited Regions:')[-1].strip()
        #     elif title == 'Assessment Overview':
        #         items = card.find_all('li', class_='list-group-item')
        #         for item in items:
        #             text = item.get_text(strip=True)
        #             if 'Total Findings:' in text:
        #                 aws_summary['total_findings'] = int(text.split(':')[-1])
        #             if 'Passed:' in text and 'Muted' not in text:
        #                 aws_summary['passed'] = int(text.split(':')[-1])
        #             if 'Failed:' in text and 'Muted' not in text:
        #                 aws_summary['failed'] = int(text.split(':')[-1])
        #             if 'Total Resources:' in text:
        #                 aws_summary['total_resources'] = int(text.split(':')[-1])

        # Findings 테이블
        findings = []
        table = soup.find('table', {'id': 'findingsTable'})
        if table:
            tbody = table.find('tbody')
            for row in tbody.find_all('tr'):
                cols = row.find_all('td')
                if not cols or len(cols) < 12: continue
                finding = {
                    'status': cols[0].get_text(strip=True),
                    'severity': cols[1].get_text(strip=True),
                    'service': cols[2].get_text(strip=True),
                    'region': cols[3].get_text(strip=True),
                    'check_id': cols[4].get_text(strip=True),
                    'check_title': cols[5].get_text(strip=True),
                    'resource_id': cols[6].get_text(strip=True),
                    'status_extended': cols[8].get_text(strip=True),
                    'risk': cols[9].get_text(strip=True),
                    'recommendation': cols[10].get_text(strip=True),
                    'compliance': cols[11].get_text(strip=True)
                }
                findings.append(finding)

        result = {
            # 'summary': summary,
            # 'aws_summary': aws_summary,
            'findings': findings
        }

        return result

    except Exception as e:
        print(f"Error parsing HTML content: {e}")
        return {"error": str(e)}


def parse_prowler_html_report(html_content, preview_length=500) -> dict:
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