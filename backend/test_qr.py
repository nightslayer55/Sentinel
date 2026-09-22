from analyzers.qr_analyzer import decode_qr


image_path = r"C:\Users\behar\Desktop\Sentinal\test_qr.png"

result = decode_qr(image_path)

print(result)