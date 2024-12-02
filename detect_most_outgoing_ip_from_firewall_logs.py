'''
Given a list of network traffic logs in the format timestamp source_ip destination_ip status, 
find:

The IP with the most outgoing requests.
The IP with the most blocked (BLOCKED) requests.

Input:
6
2024-11-26T12:00:00 192.168.1.1 10.0.0.1 ALLOWED
2024-11-26T12:01:00 192.168.1.1 10.0.0.2 BLOCKED
2024-11-26T12:02:00 10.0.0.2 192.168.1.1 ALLOWED
2024-11-26T12:03:00 192.168.1.1 10.0.0.3 BLOCKED
2024-11-26T12:04:00 10.0.0.3 192.168.1.1 BLOCKED

Output:
Most outgoing requests: 192.168.1.1
Most blocked requests: 192.168.1.1
'''
from collections import Counter
import sys

src_ip_lst = []
blocked_request_ip_lst = []

def suspicious_ip(logs):
    for log in logs: 
        timestamp, src_ip, dst_ip, status = log.split()
        src_ip_lst.append(src_ip)
        if status == 'BLOCKED':
            blocked_request_ip_lst.append(src_ip)

    most_outgoing_ip = Counter(src_ip_lst).most_common(1)
    most_blocked_request_ip = Counter(blocked_request_ip_lst).most_common(1)

    return most_outgoing_ip, most_blocked_request_ip

if __name__ == '__main__':
    #Read input
    #input = sys.stdin.readlines()
    #logs = input[1:]
    #Format output
    logs = ['2024-11-26T12:00:00 192.168.1.1 10.0.0.1 ALLOWED',
            '2024-11-26T12:01:00 192.168.1.1 10.0.0.2 BLOCKED',
            '2024-11-26T12:02:00 10.0.0.2 192.168.1.1 ALLOWED',
            '2024-11-26T12:03:00 192.168.1.1 10.0.0.3 BLOCKED',
            '2024-11-26T12:04:00 10.0.0.3 192.168.1.1 BLOCKED']
    print(f'Most outgoing requests: {suspicious_ip(logs)[0][0][0]}')
    print(f'Most blocked requests: {suspicious_ip(logs)[1][0][0]}')
        

    





  

