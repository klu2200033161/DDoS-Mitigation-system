import time

BLOCKED_IPS = {}

AUTO_BLOCK_THRESHOLD = 90

def process_detection_results(ip_list):

    global BLOCKED_IPS

    for ip in ip_list:
        if ip["risk"] >= AUTO_BLOCK_THRESHOLD and ip["ip"] not in BLOCKED_IPS:
            BLOCKED_IPS[ip["ip"]] = {
                "time": int(time.time()),
                "reason": f"Auto Block: {ip['ddos_type']} ({ip['risk']}%)"
            }

    return BLOCKED_IPS


def mark_block_status(ip_list):

    for ip in ip_list:
        if ip["ip"] in BLOCKED_IPS:
            ip["status"] = "Blocked"
            ip["is_blocked"] = True
        else:
            ip["is_blocked"] = False

    return ip_list
