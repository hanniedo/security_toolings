'''
You are tasked with detecting suspicious login activity in an authentication log.
A login attempt is flagged as suspicious if:

There are more than 3 failed login attempts from the same IP address within 10 minutes.
The same user logs in from two different IP addresses within 5 minutes.

A list of suspicious IP addresses with excessive failed attempts.
A list of users with suspicious multiple-IP logins.

Input:
logs = [
    "2024-11-01T12:00:00,user1,192.168.1.1,FAILED",
    "2024-11-01T12:03:00,user1,192.168.1.1,FAILED",
    "2024-11-01T12:06:00,user1,192.168.1.1,FAILED",
    "2024-11-01T12:08:00,user1,192.168.1.1,FAILED",
    "2024-11-01T12:09:00,user1,192.168.1.2,SUCCESS",
    "2024-11-01T12:12:00,user1,192.168.1.3,SUCCESS",
    "2024-11-01T12:15:00,user2,192.168.1.4,FAILED"
]

Output:
(['192.168.1.1'], ['user1'])

'''
from collections import defaultdict
from datetime import datetime

def suspicious_login(logs:list):

    suspicious_ips = defaultdict()
    suspicious_users = defaultdict(list)

    for log in logs:
        timestamp, user_name, ip, status = log.split()

        #1st scenario
        if status == 'FAILED':
            suspicious_ips[ip].append(datetime.strptime(timestamp, '%y-%m-%dT%H:%M:%S:'))
            flagged_ips = set()
            for ip, timestamps in suspicious_ips.items():
                if len(sorted(timestamps)) >= 3:
                    if (timestamps[:-1] - timestamps[0]).total_seconds() >= 600:
                        flagged_ips.add(ip)
        #2nd scenario
        elif status == 'SUCCESS':
            flagged_users = set()
            suspicious_users[user_name].append((timestamp,ip))
            #Remove IPs older than 5 mins
            suspicious_users[user_name] = [(t,ip) for timestamp, ip in suspicious_users[user_name] if (timestamp - t).total_seconds() <= 300]
            for username, event in suspicious_users.items():
                if len(set(ip for _ in suspicious_users[user_name])) > 1:
                    suspicious_users.add(user_name)

if __name__ == '__main__':
    suspicious_login(logs)
    
    
        

    





  

