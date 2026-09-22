import requests

url = "http://127.0.0.1:5000/api/analyze/message"

message = """
URGENT: Your account needs verification!
Please visit https://example.com/login/verify/account
to verify your account.
"""

response = requests.post(
    url,
    json={"message": message}
)

print(response.status_code)
print(response.json())