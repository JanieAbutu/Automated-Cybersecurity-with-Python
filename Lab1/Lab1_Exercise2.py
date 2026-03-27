# Login Success Rate

# Login Events
users = ["alice", "alice", "alice", "bob", "admin", "admin","charlie"]
ips = ["10.0.0.5", "10.0.0.5", "10.0.0.5", "10.0.0.8", "10.0.0.9", "10.0.0.9", "10.0.0.7"]
status = ["FAIL", "FAIL", "FAIL", "OK", "FAIL", "OK", "FAIL"]

# Known bad indicators
suspicious_ips = ["10.0.0.5", "10.0.0.66"]
suspicious_users = ["admin", "root"]

# To count OK and Fail in status
count_ok = 0
count_fail = 0

for val in status:                      # for loop to count Ok and Fail
    if val == "OK":
        count_ok += 1
    elif val == "FAIL":
        count_fail +=1

print("OK count is", count_ok)
print("FAIL count is ", count_fail)

# To detect bruteforce - 2 Consecutive fail followed by an OK

for i in range(len(status) - 2):       # for loop to detect 2 fails followed by 1 ok
    if (status[i] == "FAIL" and 
       status[i+1] == "FAIL" and 
       status[i+2] == "OK"):

       print ("BRUTEFORCE DETECTED!!!!")

