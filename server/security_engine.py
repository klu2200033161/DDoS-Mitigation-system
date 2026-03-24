# import time

# BLOCKED_IPS = {}

# AUTO_BLOCK_THRESHOLD = 90

# def process_detection_results(ip_list):

#     global BLOCKED_IPS

#     for ip in ip_list:
#         if ip["risk"] >= AUTO_BLOCK_THRESHOLD and ip["ip"] not in BLOCKED_IPS:
#             BLOCKED_IPS[ip["ip"]] = {
#                 "time": int(time.time()),
#                 "reason": f"Auto Block: {ip['ddos_type']} ({ip['risk']}%)"
#             }

#     return BLOCKED_IPS


# def mark_block_status(ip_list):

#     for ip in ip_list:
#         if ip["ip"] in BLOCKED_IPS:
#             ip["status"] = "Blocked"
#             ip["is_blocked"] = True
#         else:
#             ip["is_blocked"] = False

#     return ip_list
import time

# Store blocked IPs
BLOCKED_IPS = {}

# Risk threshold for auto blocking
AUTO_BLOCK_THRESHOLD = 90

# Block duration (seconds)
BLOCK_DURATION = 300   # 5 minutes


def process_detection_results(ip_list):

    global BLOCKED_IPS

    current_time = int(time.time())

    for ip in ip_list:

        if ip["risk"] >= AUTO_BLOCK_THRESHOLD and ip["ip"] not in BLOCKED_IPS:

            BLOCKED_IPS[ip["ip"]] = {
                "time": current_time,
                "reason": f"Auto Block: {ip['ddos_type']} ({ip['risk']}%)"
            }

    return BLOCKED_IPS


def mark_block_status(ip_list):

    for ip in ip_list:

        if ip["ip"] in BLOCKED_IPS:

            ip["status"] = "Blocked"
            ip["is_blocked"] = True

        else:

            ip["status"] = "Active"
            ip["is_blocked"] = False

    return ip_list


def unblock_expired_ips():

    global BLOCKED_IPS

    current_time = int(time.time())

    expired = []

    for ip, data in BLOCKED_IPS.items():

        if current_time - data["time"] > BLOCK_DURATION:
            expired.append(ip)

    for ip in expired:
        del BLOCKED_IPS[ip]

    return BLOCKED_IPS


def manual_unblock(ip):

    if ip in BLOCKED_IPS:
        del BLOCKED_IPS[ip]
        return True

    return False


def get_blocked_ips():

    return BLOCKED_IPS