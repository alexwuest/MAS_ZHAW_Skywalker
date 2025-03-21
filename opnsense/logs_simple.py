import api_logs
import time

import config

search_address = input("Enter IP address to filter logs (optional): ")

while True:
    # Clear the set to avoid accumulating old results
    config.IP_TABLE.clear()

    # Run the log parsing function
    if search_address:
        api_logs.parse_logs(search_address)
    else:
        api_logs.parse_logs()

    # Wait for 10 seconds before repeating
    time.sleep(10)

    # Print unique IPs after each cycle
    print(config.IP_TABLE)

