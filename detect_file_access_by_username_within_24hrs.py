'''
You are given a log of file access attempts. Each entry contains timestamp username 
filename action. Detect users who accessed sensitive files (confidential.txt) 
more than 3 times within 24 hours.

Input:
6
2024-11-26T12:00:00 alice confidential.txt READ
2024-11-26T12:01:00 alice confidential.txt READ
2024-11-26T12:02:00 alice confidential.txt WRITE
2024-11-26T12:03:00 alice confidential.txt READ
2024-11-26T12:04:00 bob confidential.txt READ
2024-11-26T12:05:00 bob confidential.txt READ

Output:
Flagged user: alice
'''

from datetime import datetime
from collections import defaultdict

#Create a dict to store the number of times a user accesses confidental files
access_attempt_by_user = defaultdict(list)

def suspicious_user(logs):
    for log in logs:
        timestamp, user_name, file_name, _ = log.split()
        if file_name == 'confidential.txt':
            #Convert timestamp to a datetime object
            access_attempt_by_user[user_name].append(datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S'))
    
    suspicious_user = set()
    for user_name, timestamps in access_attempt_by_user.items():
        timestamps.sort()
        #Access threshold is more than 3 times
        if len(timestamps) >= 3:
            #Take the difference in timestamps between the last and the 1st attemps.
            #If it is more than 8600 secs (24 hrs), collect it.
            if (timestamps[-1] - timestamps[0]).total_seconds() <= 8600:
                suspicious_user.add(user_name)
    return suspicious_user
    
# Input reading and output writing
if __name__ == "__main__":
    '''
    #To read input programmatically
    import sys
    input = sys.stdin.readlines()
    logs = input[1:]
    '''
    #Hardcoded input for testing
    input = [6,
            '2024-11-26T10:00:00 alice confidential.txt READ',
            '2024-11-26T10:01:00 alice confidential.txt READ',
            '2024-11-26T11:02:00 alice confidential.txt WRITE',
            '2024-11-26T12:03:00 alice confidential.txt READ',
            '2024-11-26T12:04:00 bob confidential.txt READ',
            '2024-11-26T12:05:00 bob confidential.txt READ]']
    logs = input[1:]
    for user in suspicious_user(logs):
         print(user)

 
    
