import re


def extract_urls(message):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, message)


def analyze_message(message):
    if not message or not message.strip():
        return {
            "valid": False,
            "error": "No message provided"
        }

    urls = extract_urls(message)

    return {
        "valid": True,
        "message": message,
        "urls": urls,
        "url_count": len(urls)
    }