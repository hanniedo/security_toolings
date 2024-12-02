'''
Detect directory traversal attacks in web server logs. Directory traversal attacks 
can be identified by the presence of patterns like ../ or ..\ in the requested URLs.

Sample input
5 #Number of log items
192.168.1.1 - GET /index.html
192.168.1.2 - GET /admin/../../etc/passwd
192.168.1.3 - POST /login
192.168.1.4 - GET /images/../secret/file.txt
192.168.1.5 - GET /static/js/app.js

Output
192.168.1.2 - GET /admin/../../etc/passwd
192.168.1.4 - GET /images/../secret/file.txt
'''
import re

def detect_directory_traversal(logs:list):
    traversal_pattern = re.compile(r'\.\./|\.\.\\')
    suspicious_log = []
    for log in logs:
        if traversal_pattern.search(log):
        #if '../' in log or '../' in log:
            suspicious_log.append(log)
    return suspicious_log

if __name__ == '__main__':
    
    '''
    # To hanle user imput
    n = int(input().strip())
    logs = [input().strip() for _ in range(n)]
    result = detect_directory_traversal(logs)
    '''
    #For testing
    logs = ['192.168.1.1 - GET /index.html', 
            '192.168.1.2 - GET /admin/../../etc/passwd',
            '192.168.1.3 - POST /login',
            '192.168.1.4 - GET /images/../secret/file.txt',
            '192.168.1.5 - GET /static/js/app.js']
    result = detect_directory_traversal(logs)
    for i in result:
        print (i)

    
        

    





  

