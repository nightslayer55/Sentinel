import requests

url = "http://127.0.0.1:5000/api/analyze/qr"

image_path = r"C:\Users\behar\Desktop\Sentinal\test_qr.png"

with open(image_path, "rb") as image:
    response = requests.post(
        url,
        files={"image": image}
    )

print(response.status_code)
print(response.json())