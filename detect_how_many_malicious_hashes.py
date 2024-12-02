'''
You are given a list of file hashes and a list of known malicious hashes. 
Determine how many files in the list are malicious.

Input:
abc123 def456 ghi789 abc123 xyz000
bc123 xyz000 malware999

Output:
2 malicious files detected.
'''
from collections import Counter
import sys


def malicious_hash(hashes, malicious_hashes):
    #Convert list to hash to be able to intersect them later
    hashes_set = set(hashes)
    malicious_set = set(malicious_hashes)

    return len(hashes_set.intersection(malicious_set))
    

if __name__ == '__main__':
    '''
    #Read input
    input = sys.stdin.readlines()
    hashes = []
    malicious_hashes = []
    for line in input:
        hashes.append(line[0].split())
        malicious_hashes.append(line[1].split())
    #for line 
    #Format output
    '''
    hashes = ['abc123', 'def456', 'ghi789', 'abc123', 'xyz000']
    malicious_hashes = ['bc123', 'xyz000', 'malware999']
    print(f'{malicious_hash(hashes, malicious_hashes)} is detected.')
        

    





  

