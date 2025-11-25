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

def get_deployment_status(yaml_file):
    cmd = ["eac", "deployment", "status", "-f", yaml_file]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Status command Failed: {result.stderr}")
    return result.stdout

#parse status

def parse_status(output)
    match = re.search(r"Status:\s*(\w+)", output)
    if match:
        return match.group(1).lower() #success or failure
    return None

#main
def main(yaml_file, log_file):
    logger = setup_logger(log_file)
    logger.info(f"checking deployment status: {yaml_file}")

    try:
        output = get_deployment_status(yaml_file)
    except Exception as e:
        logger.error(f"Failed  to get deployment status: {e}")

    status = parse_status(output)

    if status == "Success":
        logger.info("Deploymet Status: SUCCESS")
        sys.exit(0)
    elif status == "Failure":
        logger.info("Deploymet Status: FAILURE")
        sys.exit(1)
    else:
        logger.info("Could not determine deployment Status from output.")
        logger.info(output)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python deployment_status_check.py <deployment.yaml> <deployment_status.log>")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2])
