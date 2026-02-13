import streamlit as st
import requests
import json
import os
from datetime import datetime
from scanners import WebScanner
from config import CONFIG

st.set_page_config(page_title="🔒 WebSecureScan", layout="wide")

st.title("🔒 WebSecureScan v2.0")
st.markdown("**Free Online Web Vulnerability Scanner** ⚡ *Ethical use only*")

# Input form
col1, col2 = st.columns([4,1])
with col1:
    target = st.text_input("🎯 Target URL", value="https://scanme.nmap.org",
                          placeholder="https://example.com")
with col2:
    timeout = st.number_input("⏱️ Timeout", 10, 60, 30)

if st.button("🚀 RUN SCAN", type="primary"):
    if target and target.startswith(('http://','https://')):
        with st.spinner(f"🔍 Scanning {target}..."):
            try:
                config = CONFIG.copy()
                config['timeout'] = timeout
                scanner = WebScanner(target, config)
                scanner.run_full_scan()
                
                # Results
                st.success("✅ Scan Complete!")
                
                # Metrics
                c1, c2, c3 = st.columns(3)
                total_issues = len(scanner.results['issues'])
                c1.metric("🔴 Issues", total_issues)
                c2.metric("🖥️ Server", scanner.results['info'].get('server', 'Unknown'))
                c3.metric("⏰ Time", scanner.results['timestamp'][:16])
                
                # Issues list
                if total_issues > 0:
                    st.subheader(f"📋 {total_issues} Security Issues Found")
                    for issue in sorted(scanner.results['issues'], 
                                      key=lambda x: {'critical':4,'high':3,'medium':2,'low':1}.get(x['severity'],0), 
                                      reverse=True):
                        severity_color = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}.get(issue['severity'],"⚪")
                        with st.expander(f"{severity_color} [{issue['severity'].upper()}] {issue['title']}"):
                            st.write(f"**Category:** `{issue['category']}`")
                            st.write(f"**Risk:** {issue['description']}")
                            if issue.get('evidence'):
                                st.code(json.dumps(issue['evidence'], indent=2))
                else:
                    st.balloons()
                    st.success("🎉 Clean scan! No major issues detected.")
                
                # Download
                report_json = json.dumps(scanner.results, indent=2)
                st.download_button("📥 Download Full Report", report_json,
                                 f"websecurescan-{target.split('//')[1].replace('/','_')}-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                 "application/json")
                
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
                st.info("💡 Check URL format or try shorter timeout")
    else:
        st.warning("⚠️ Enter valid URL (http:// or https://)")

st.markdown("---")
st.markdown("""
*🔒 Ethical scanner - Only test sites you own/have permission for*  
**Made with Streamlit + WebSecureScan** | [GitHub](https://github.com/)
""")
