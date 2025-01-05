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
from datetime import datetime 
from collections import defaultdict

def suspicious_login_detection(logs):

    #A list of suspicious IP addresses with excessive failed attempts.
    suspicious_ips = set()
    #A list of users with suspicious multiple-IP logins.
    suspicious_users = set()
    #Initial a dict to store timestamp of the failed login attempts by ip
    failed_attempts_by_ip = defaultdict(list)
    #Initiate a dict to store ips of the success login attempts by username
    success_attempts_by_user = defaultdict(list)

    def log_parser(log):
        timestamp, username, ip, status = log.split(',')
        normalized_timestamp = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S')
        return {'timestamp': normalized_timestamp, 
                'username': username,
                'ip': ip,
                'status': status}
    for log in logs:
        parsed_log = log_parser(log)
        timestamp = parsed_log.get('timestamp', '')
        username = parsed_log.get('username', '')
        ip = parsed_log.get('ip')
        status = parsed_log.get('status')

        #1st scenario: There are more than 3 failed login attempts from the same IP address within 10 minutes.
        if status == 'FAILED':
            failed_attempts_by_ip[ip].append(timestamp)
            #Exclude timestamps that are outside of the 10 min window.
            failed_attempts_by_ip[ip] = [t for t in failed_attempts_by_ip[ip] if (timestamp-t).total_seconds() <= 600]
            if len(failed_attempts_by_ip[ip]) >= 3:
                 suspicious_ips.add(ip)

        #2nd scenario: The same user logs in from two different IP addresses within 5 minutes.
        elif status == 'SUCCESS':
            success_attempts_by_user[username].append((timestamp, ip))
            #Exclude timestamps that are outside of the 5 min window 
            success_attempts_by_user[username] = [(t, ip) for t,ip in success_attempts_by_user[username] if (timestamp -t).total_seconds() <= 300]
            for username, event in success_attempts_by_user.items():
                if len(set(ip for ip in event)) > 1 :
                   suspicious_users.add(username)

    return suspicious_ips, suspicious_users

if __name__ == '__main__':
    logs = [
    "2024-11-01T12:00:00,user1,192.168.1.1,FAILED",
    "2024-11-01T12:03:00,user1,192.168.1.1,FAILED",
    "2024-11-01T12:06:00,user1,192.168.1.1,FAILED",
    "2024-11-01T12:08:00,user1,192.168.1.1,FAILED",
    "2024-11-01T12:09:00,user1,192.168.1.2,SUCCESS",
    "2024-11-01T12:12:00,user1,192.168.1.3,SUCCESS",
    "2024-11-01T12:15:00,user2,192.168.1.4,FAILED"
]
    res = suspicious_login_detection(logs)
    print(res)
    
    
        

    





  

