def check_ip(ip):
    suspicious_ranges = ["41.", "92.", "103."]
    for r in suspicious_ranges:
        if ip.startswith(r):
            return True
    return False