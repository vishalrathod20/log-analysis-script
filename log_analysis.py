import re
from collections import defaultdict
import csv

# Parse the log file
def parse_log_file(log_file_path):
    ip_request_count = defaultdict(int)  # Count requests per IP address
    endpoint_count = defaultdict(int)  # Count requests per endpoint
    failed_login_attempts = defaultdict(int)  # Track failed login attempts per IP address
    suspicious_threshold = 5  # Threshold for suspicious activity (failed login attempts)

    # Regex to match log line pattern
    log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) .*? "(?P<method>\S+) (?P<endpoint>\S+) .*" (?P<status>\d+)'

    with open(log_file_path, 'r') as file:
        for line in file:
            match = re.match(log_pattern, line)
            if match:
                ip = match.group('ip')
                method = match.group('method')
                endpoint = match.group('endpoint')
                status = int(match.group('status'))

                # Count requests per IP
                ip_request_count[ip] += 1

                # Count requests per endpoint
                endpoint_count[endpoint] += 1

                # Count failed login attempts
                if method == "POST" and status == 401:  # Detect failed login attempts (status 401)
                    failed_login_attempts[ip] += 1

    return ip_request_count, endpoint_count, failed_login_attempts, suspicious_threshold

# Identify the most accessed endpoint
def find_most_accessed_endpoint(endpoint_count):
    return max(endpoint_count.items(), key=lambda x: x[1])

# Detect suspicious IPs based on failed login attempts
def detect_suspicious_ips(failed_login_attempts, threshold):
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count >= threshold}
    return suspicious_ips

# Save results to CSV
def save_results_to_csv(ip_request_count, most_accessed_endpoint, suspicious_ips, output_csv_file):
    with open(output_csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write IP Address Request Counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        writer.writerow([])  # Blank line for separation

        # Write Most Accessed Endpoint
        writer.writerow(["Most Frequently Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])  # Blank line for separation

        # Write Suspicious Activity
        writer.writerow(["IP Address", "Failed Login Count"])
        if suspicious_ips:
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])
        else:
            writer.writerow(["No suspicious activity detected", "N/A"])

# Main function
def main():
    log_file_path = "C:/Users/vishal rathod/Downloads/python intern/sample.log"  # Path to the log file
    output_csv_file = 'log_analysis_results.csv'  # Output CSV file name

    # Parse the log file
    ip_request_count, endpoint_count, failed_login_attempts, suspicious_threshold = parse_log_file(log_file_path)

    # Identify the most accessed endpoint
    most_accessed_endpoint = find_most_accessed_endpoint(endpoint_count)

    # Detect suspicious IPs
    suspicious_ips = detect_suspicious_ips(failed_login_attempts, suspicious_threshold)

    # Save results to CSV
    save_results_to_csv(ip_request_count, most_accessed_endpoint, suspicious_ips, output_csv_file)

    # Display results
    print("IP Address Request Counts:")
    for ip, count in sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    print(f"\nResults saved to {output_csv_file}")

# Run the script
if __name__ == "__main__":
    main()
