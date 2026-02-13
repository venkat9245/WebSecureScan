from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf_report(target, findings, output="report.pdf"):
    try:
        doc = SimpleDocTemplate(output, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        story.append(Paragraph(f"<b>WebSecureScan Report - {target}</b>", styles['Title']))
        story.append(Spacer(1, 12))
        
       severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
for finding in findings:
    sev = finding.get('severity', 'INFO') # Default to INFO if missing
    severity_count[sev] = severity_count.get(sev, 0) + 1

        
        summary_table = Table([['Severity', 'Count'], 
                              ['CRITICAL', severity_count['CRITICAL']],
                              ['HIGH', severity_count['HIGH']],
                              ['MEDIUM', severity_count['MEDIUM']]])
        story.append(summary_table)
        
        doc.build(story)
        print(f"[+] PDF Report saved: {output}")
    except ImportError:
        print("[-] PDF generation skipped - install reportlab")

def generate_html_report(target, findings, output="report.html"):
    html = f"""
    <!DOCTYPE html>
    <html><head><title>WebSecureScan Report</title></head>
    <body>
    <h1>WebSecureScan - {target}</h1>
    <h2>Findings ({len(findings)} total):</h2>
    <ul>
    """
    for finding in findings:
        html += f"<li><b>{finding['severity']}</b>: {finding['type']} - {finding['details']}</li>\n"
    html += "</ul></body></html>"
    
    with open(output, 'w') as f:
        f.write(html)
    print(f"[+] HTML Report saved: {output}")
