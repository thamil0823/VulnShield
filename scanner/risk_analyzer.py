def generate_findings(checks):

    findings = []

    recommendations = {
        "X-Frame-Options":
            "Set X-Frame-Options header to DENY or SAMEORIGIN.",

        "Content-Security-Policy":
            "Implement a strong Content-Security-Policy header.",

        "Strict-Transport-Security":
            "Enable HSTS to force HTTPS connections.",

        "X-Content-Type-Options":
            "Set X-Content-Type-Options to nosniff.",

        "Referrer-Policy":
            "Add a Referrer-Policy header.",

        "Permissions-Policy":
            "Restrict browser permissions using Permissions-Policy."
    }

    for header, status in checks.items():

        if status == "Missing":

            severity = "Medium"

            if header in [
                "Content-Security-Policy",
                "Strict-Transport-Security"
            ]:
                severity = "High"

            findings.append({
                "Severity": severity,
                "Issue": f"Missing {header}",
                "Status": "Vulnerable",
                "Recommendation":
                    recommendations.get(
                        header,
                        "Review configuration."
                    )
            })

    return findings