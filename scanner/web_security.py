import requests

def check_headers(url):

    try:

        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent":"Mozilla/5.0"}
        )

        headers = response.headers

        checks = {

            "X-Frame-Options":
                "Present" if "X-Frame-Options" in headers else "Missing",

            "Content-Security-Policy":
                "Present" if "Content-Security-Policy" in headers else "Missing",

            "Strict-Transport-Security":
                "Present" if "Strict-Transport-Security" in headers else "Missing",

            "X-Content-Type-Options":
                "Present" if "X-Content-Type-Options" in headers else "Missing",

            "Referrer-Policy":
                "Present" if "Referrer-Policy" in headers else "Missing",

            "Permissions-Policy":
                "Present" if "Permissions-Policy" in headers else "Missing"
        }

        passed = sum(
            1 for v in checks.values()
            if v == "Present"
        )

        total = len(checks)

        score = int((passed / total) * 100)

        if score >= 80:
            risk = "LOW"
        elif score >= 50:
            risk = "MEDIUM"
        else:
            risk = "HIGH"

        return {
            "Status Code": response.status_code,
            "Server": headers.get("Server","Unknown"),
            "Content Type": headers.get("Content-Type","Unknown"),
            "Score": score,
            "Risk": risk,
            "Passed": passed,
            "Failed": total - passed,
            "Checks": checks
        }

    except Exception as e:

        return {
            "Error": str(e)
        }