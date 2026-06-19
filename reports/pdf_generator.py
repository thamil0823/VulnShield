from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib.styles import getSampleStyleSheet

from datetime import datetime


def generate_pdf(
    target,
    results,
    ssl_results,
    findings
):

    filename = "Vulnerability_Report.pdf"

    doc = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    elements = []

    title = Paragraph(
        "Cyber Security Vulnerability Report",
        styles["Title"]
    )

    elements.append(title)

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            f"<b>Target:</b> {target}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Generated:</b> {datetime.now()}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Security Score:</b> {results['Score']}/100",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Risk Level:</b> {results['Risk']}",
            styles["BodyText"]
        )
    )

    elements.append(
        Spacer(1, 20)
    )

    elements.append(
        Paragraph(
            "Executive Summary",
            styles["Heading2"]
        )
    )

    elements.append(
        Paragraph(
            f"""
            The target website was analyzed
            for common HTTP security headers,
            SSL configuration and security
            best practices.

            Overall Risk Level:
            {results['Risk']}
            """,
            styles["BodyText"]
        )
    )

    elements.append(
        Spacer(1, 20)
    )

    elements.append(
        Paragraph(
            "Security Header Findings",
            styles["Heading2"]
        )
    )

    for item in findings:

        elements.append(
            Paragraph(
                f"""
                <b>{item['Severity']}</b> -
                {item['Issue']}
                """,
                styles["BodyText"]
            )
        )

        elements.append(
            Paragraph(
                item["Recommendation"],
                styles["BodyText"]
            )
        )

    elements.append(
        Spacer(1, 20)
    )

    elements.append(
        Paragraph(
            "SSL Information",
            styles["Heading2"]
        )
    )

    for key, value in ssl_results.items():

        elements.append(
            Paragraph(
                f"{key}: {value}",
                styles["BodyText"]
            )
        )

    doc.build(elements)

    return filename