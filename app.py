import streamlit as st
import pandas as pd
import plotly.express as px

from scanner.nmap_scan import run_scan
from scanner.web_security import check_headers
from scanner.ssl_checker import check_ssl
from scanner.risk_analyzer import generate_findings
from reports.pdf_generator import generate_pdf

st.set_page_config(
    page_title="Cyber Security Scanner",
    page_icon="🔒",
    layout="wide"
)

st.title("🔒 Cyber Security Vulnerability Scanner")

target = st.text_input(
    "Enter IP Address or Website"
)

if st.button("Scan"):

    if target:

        # WEBSITE SECURITY SCAN
        if target.startswith("http"):

            results = check_headers(target)

            hostname = (
                target
                .replace("https://", "")
                .replace("http://", "")
                .split("/")[0]
            )

            ssl_results = check_ssl(hostname)

            findings = generate_findings(
                results["Checks"]
            )

            st.success(
                "✅ Website Scan Completed"
            )

            # Executive Summary

            st.subheader(
                "📋 Executive Summary"
            )

            st.info(
                f"""
Target: {target}

Security Score: {results['Score']}/100

Risk Level: {results['Risk']}

Passed Checks: {results['Passed']}

Failed Checks: {results['Failed']}
"""
            )

            # Dashboard Cards

            col1, col2, col3, col4 = st.columns(4)

            col1.metric(
                "Security Score",
                f"{results['Score']}/100"
            )

            col2.metric(
                "Risk Level",
                results["Risk"]
            )

            col3.metric(
                "Passed Checks",
                results["Passed"]
            )

            col4.metric(
                "Failed Checks",
                results["Failed"]
            )

            # Pie Chart

            chart_df = pd.DataFrame({
                "Status": [
                    "Passed",
                    "Failed"
                ],
                "Count": [
                    results["Passed"],
                    results["Failed"]
                ]
            })

            fig = px.pie(
                chart_df,
                names="Status",
                values="Count",
                title="Security Header Analysis"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

            # Website Information

            st.subheader(
                "🌐 Website Information"
            )

            info_df = pd.DataFrame({
                "Item": [
                    "Status Code",
                    "Server",
                    "Content Type"
                ],
                "Value": [
                    results["Status Code"],
                    results["Server"],
                    results["Content Type"]
                ]
            })

            st.table(info_df)

            # Security Headers

            st.subheader(
                "🛡 Security Headers"
            )

            headers_df = pd.DataFrame(
                list(
                    results["Checks"].items()
                ),
                columns=[
                    "Header",
                    "Status"
                ]
            )

            st.table(headers_df)

            # Vulnerability Findings

            st.subheader(
                "🚨 Vulnerability Findings"
            )

            if findings:

                findings_df = pd.DataFrame(
                    findings
                )

                st.dataframe(
                    findings_df,
                    use_container_width=True
                )

            else:

                st.success(
                    "No vulnerabilities found."
                )

            # SSL Information

            st.subheader(
                "🔐 SSL Information"
            )

            ssl_df = pd.DataFrame(
                list(
                    ssl_results.items()
                ),
                columns=[
                    "SSL Check",
                    "Result"
                ]
            )

            st.table(ssl_df)

            # PDF REPORT

            pdf_file = generate_pdf(
                target,
                results,
                ssl_results,
                findings
            )

            with open(
                pdf_file,
                "rb"
            ) as file:

                st.download_button(
                    label="📄 Download Vulnerability Report",
                    data=file,
                    file_name=pdf_file,
                    mime="application/pdf"
                )

        # PORT SCAN

        else:

            results = run_scan(target)

            st.success(
                "✅ Port Scan Completed"
            )

            if results:

                df = pd.DataFrame(results)

                st.metric(
                    "Open Ports",
                    len(results)
                )

                st.dataframe(
                    df,
                    use_container_width=True
                )

            else:

                st.warning(
                    "No open ports found"
                )