# Log Analysis Script

## Description
This Python script analyzes a web server log file to gather insights into request patterns, identify potential security threats, and generate a detailed report. The main functionalities include:

- **Counting Requests per IP Address**: The script counts how many requests each IP address made in the log file.
- **Identifying the Most Frequently Accessed Endpoint**: It identifies which endpoint (e.g., `/home`, `/login`, `/about`, etc.) was accessed the most by users.
- **Detecting Suspicious Activity**: The script detects suspicious activity by flagging IP addresses with multiple failed login attempts (HTTP status `401`).
- **Output to CSV**: The results are saved in a CSV file, making it easy to visualize and further analyze the data.

## Features
1. **Log Parsing**: The log file is parsed using regular expressions to extract key details such as IP address, HTTP method, endpoint, and status code.
2. **Request Count per IP**: The script tracks the number of requests made by each IP address, providing insights into usage patterns.
3. **Most Accessed Endpoint**: It identifies and reports the most frequently accessed endpoint in the log file.
4. **Suspicious Activity Detection**: The script flags IP addresses with multiple failed login attempts as suspicious, helping to identify potential brute-force attacks or unauthorized access attempts.
5. **CSV Export**: All analysis results are saved into a CSV file for further examination, with clear sections for:
   - Request counts per IP address
   - The most accessed endpoint
   - Suspicious activity (if any)

## Usage
1. **Prepare the Log File**: Ensure you have a valid web server log file (e.g., `sample.log`).
2. **Set the Log File Path**: Modify the `log_file_path` variable in the script to point to the location of your log file.
3. **Run the Script**: Execute the script, and it will process the log file to analyze requests, endpoints, and detect suspicious activity.
4. **Check the Output**: The script will display the results in the console and save them to a CSV file for further analysis.

## Example Output
The script outputs the following information:

- **IP Address Request Counts**: A list of IP addresses and the number of requests each made.
- **Most Frequently Accessed Endpoint**: The endpoint that was accessed the most.
- **Suspicious Activity**: If any IP addresses have multiple failed login attempts, they are flagged as suspicious.

### Example CSV Output:
If suspicious activity is detected:

### IP Address and Request Count
| IP Address      | Request Count |
|-----------------|---------------|
| 192.168.1.1     | 6             |
| 203.0.113.5     | 9             |
| 10.0.0.2        | 7             |
| 198.51.100.23   | 5             |
| 192.168.1.100   | 4             |

### Most Frequently Accessed Endpoint
| Endpoint        | Access Count |
|-----------------|--------------|
| /home           | 6            |

### IP Address and Failed Login Count
| IP Address      | Failed Login Count |
|-----------------|--------------------|
| 203.0.113.5     | 5                  |
| 192.168.1.100   | 4                  |

### Suspicious Activity Detection
If no suspicious activity is detected:
| IP Address      | Failed Login Count |
|-----------------|--------------------|
| No suspicious activity detected | N/A |


## Requirements
- Python 3.x
- No external libraries required (uses built-in libraries: `re`, `csv`, and `collections`).

## Conclusion
This script is useful for analyzing server logs, detecting potential security issues, and tracking request patterns, providing insights into both server usage and security threats.
