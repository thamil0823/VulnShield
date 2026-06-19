import ssl
import socket

from datetime import datetime

def check_ssl(hostname):

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443)
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as ssock:

                cert = ssock.getpeercert()

                expiry_date = datetime.strptime(
                    cert["notAfter"],
                    "%b %d %H:%M:%S %Y %Z"
                )

                days_left = (
                    expiry_date - datetime.now()
                ).days

                issuer = cert["issuer"][0][0][1]

                return {

                    "SSL Status":
                        "Valid",

                    "Issuer":
                        issuer,

                    "Days Remaining":
                        days_left,

                    "Expiry Date":
                        str(expiry_date.date())
                }

    except Exception as e:

        return {

            "SSL Status":
                "Invalid",

            "Error":
                str(e)
        }