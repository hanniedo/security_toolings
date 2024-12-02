'''
You are tasked with enriching log entries by appending additional metadata from 
external sources.

Input
logs = [
    "2024-11-01T12:00:00,101,login",
    "2024-11-01T12:05:00,102,logout",
    "2024-11-01T12:10:00,103,access_file"
]
metadata = {
    "101": {"username": "alice", "department": "engineering"},
    "102": {"username": "bob", "department": "marketing"},
    "103": {"username": "charlie", "department": "finance"}
}

Output
[
    "2024-11-01T12:00:00,101,alice,engineering,login",
    "2024-11-01T12:05:00,102,bob,marketing,logout",
    "2024-11-01T12:10:00,103,charlie,finance,access_file"
]
    
    '''
def enrichment(logs, metadata):
    #Parse data from logs
    enriched = []
    for log in logs:
        timestamp, id, action = log.split(',')
        for i in metadata:
            if i == id:
                data = metadata.get(i, '')
                user_name = data.get('username', '')
                department = data.get('department', '')
                item = f"{timestamp}, {id}, {user_name}, {department}, {action}"
            else:
                item = f"{timestamp}, {id}, 'unknown', 'unknown', {action}"
        enriched.append(item)
    return enriched

if __name__ == '__main__':
    logs = [
    "2024-11-01T12:00:00,101,login",
    "2024-11-01T12:05:00,102,logout",
    "2024-11-01T12:10:00,103,access_file",
    "2024-11-01T12:15:00,104,delete_file"
]
    metadata = {
    "101": {"username": "alice", "department": "engineering"},
    "102": {"username": "bob", "department": "marketing"},
    "103": {"username": "charlie", "department": "finance"}
}
    print(enrichment(logs, metadata))

        


    
        

    





  

