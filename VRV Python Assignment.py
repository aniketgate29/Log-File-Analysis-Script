import re
import csv
from collections import Counter, defaultdict

# File paths
log_file = "sample.log"
output_file = "log_analysis_results.csv"

# Configuration
FAILED_LOGIN_THRESHOLD = 10

# Functions
def parse_log(file_path):
    ip_requests = Counter()
    endpoints = Counter()
    failed_logins = defaultdict(int)
    
    with open(file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            ip = ip_match.group(1) if ip_match else None
            
            # Extract endpoint
            endpoint_match = re.search(r'"(?:GET|POST) (/\S+)', line)
            endpoint = endpoint_match.group(1) if endpoint_match else None
            
            # Extract status code
            status_match = re.search(r'HTTP/\d\.\d" (\d{3})', line)
            status_code = int(status_match.group(1)) if status_match else None
            
            # Increment counters
            if ip:
                ip_requests[ip] += 1
            if endpoint:
                endpoints[endpoint] += 1
            if status_code == 401 and ip:
                failed_logins[ip] += 1

    return ip_requests, endpoints, failed_logins

def save_to_csv(data, columns, file_path, mode='w'):
    with open(file_path, mode, newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(columns)
        writer.writerows(data)

# Process log file
ip_requests, endpoints, failed_logins = parse_log(log_file)

# Calculate results
sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
most_accessed_endpoint = endpoints.most_common(1)[0]
suspicious_activity = [(ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD]

# Print results
print("IP Address           Request Count")
for ip, count in sorted_ip_requests:
    print(f"{ip:<20}{count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

if suspicious_activity:
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity:
        print(f"{ip:<20}{count}")
else:
    print("\nNo suspicious activity detected.")

# Save results to CSV
save_to_csv(sorted_ip_requests, ["IP Address", "Request Count"], output_file)
save_to_csv([most_accessed_endpoint], ["Endpoint", "Access Count"], output_file, mode='a')
save_to_csv(suspicious_activity, ["IP Address", "Failed Login Count"], output_file, mode='a')

print(f"\nResults saved to {output_file}")





