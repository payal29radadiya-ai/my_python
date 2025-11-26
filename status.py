import subprocess
import json
import sys
import logging
import boto3
import re

#Configure Logging
def setup_logger(log_file):
    logger = logging.getLogger("deployment_status_check")
    logger.setLevel(logging.INFO)
    # Console handler
    console_handler = logging.streamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler (console_handler)
    logger.addHandler(file_handler)
    return logger

#run status command

#main
def main(yaml_file, log_file):
    logger = setup_logger(log_file)
    logger.info(f"Checking deployment status from: {json_file}")

    try:
        with open(json_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read JSON file: {e}")
        print(1)
        sys.exit(1)

    status = str(data.get("Status", "")).lower()
    if status == "success":
        logger.info("Deploymet Status: SUCCESS")
        print(0)
        sys.exit(0)
    else:
        logger.info("Deploymet Status: FAILURE")
        print(1)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python status.py <dummy.json> <output.log>")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2])
