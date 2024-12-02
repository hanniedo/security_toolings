'''
Detect Suspicious Network Ports

Problem Statement: Analyze a list of network connections and identify all 
connections to ports not in a given whitelist.

Input
3
192.168.1.10:22
192.168.1.20:8080
192.168.1.30:1234
22,443,80

Output:
192.168.1.20:8080
192.168.1.30:1234

'''

def suspicious_port(logs, whitelist):
    output = []
    for log in logs:
        ip, port = log.split(':')
        port = int(port)
        if port == 8080:
            port = 80
        if port not in whitelist:
            output.append(log)

    return output

if __name__ == '__main__':
    
    '''
    n = int(input())
    logs = [input().strip() for _ in range(n)]
    whitelist = list(map(int, input().strip().split(',')))
    result = suspicious_port(logs, whitelist)
    '''
    logs = ['192.168.1.10:22', '192.168.1.20:8080', '192.168.1.30:1234']
    whitelist = [22, 443, 80]
    result = suspicious_port(logs, whitelist)
    for i in result:
        print (i)

    
        

    





  

