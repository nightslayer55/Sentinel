import cv2


def decode_qr(image_path):
    detector = cv2.QRCodeDetector()

    image = cv2.imread(image_path)

    if image is None:
        return {
            "success": False,
            "error": "Unable to read the image"
        }

    data, points, _ = detector.detectAndDecode(image)

    if not data:
        return {
            "success": False,
            "error": "No QR code could be detected"
        }

    return {
        "success": True,
        "data": data
    }