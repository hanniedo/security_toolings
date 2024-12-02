'''
Detect if an account has more than 5 failed login attempts in 10 minutes. 
Each log entry contains timestamp username status.

Sample input:

7 #Number of line items
2024-11-26T12:00:00 alice FAIL
2024-11-26T12:01:00 alice FAIL
2024-11-26T12:02:00 alice FAIL
2024-11-26T12:03:00 alice FAIL
2024-11-26T12:04:00 alice FAIL
2024-11-26T12:05:00 alice FAIL
2024-11-26T12:06:00 bob FAIL

'''

from datetime import datetime
from collections import defaultdict
import sys

#Create a dict to store failed attempt with timestamps for each user
fail_timestampt_by_user = defaultdict(list)

def detect_fail_logins(logs):
    for log in logs:
        timestamp, name, status = log.split()
        #Format timestamp to a datetime object
        formatted_timestamp = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S')
        if status == 'FAIL':
            fail_timestampt_by_user[name].append(formatted_timestamp)
        
    for name, timestamps in fail_timestampt_by_user.items():
        #Only procedd when failed attempt threshold >=5
        if len(timestamps) >= 5:
            sorterd_timestamp = sorted(timestamps)
            if (sorterd_timestamp[-1] - sorterd_timestamp[0]).total_seconds() <= 600:
                return 'ALERT'
    return 'SAFE'

# Input reading and output writing
if __name__ == "__main__":
    '''
    #To read input programmatically
    input = sys.stdin.readlines()
    logs = []
    for i in input:
        if i.isint() == 'True':
            continue
        else:
            logs.append(i)
    print(detect_fail_logins(logs))
    ''' 
    #For testing
    logs = ['2024-11-26T12:00:00 alice FAIL',
            '2024-11-26T12:01:00 alice FAIL',
            '2024-11-26T12:02:00 alice FAIL',   
            '2024-11-26T12:03:00 alice FAIL',
            '2024-11-26T12:04:00 alice FAIL',
            '2024-11-26T12:05:00 alice FAIL',
            '2024-11-26T12:06:00 alice FAIL',
            '2024-11-26T12:07:00 bob FAIL']
    
    print(detect_fail_logins(logs))
  
    
