import subprocess
import json
import sys
import logging
import boto3
from botocore.exceptions import ClientError

#Configure Logging
def setup_logger(log_file):
    logger = logging.getLogger("infra_health_check")
    logger.setLevel(logging.INFO)
    # Console handler
    console_handler = logging.streamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_formatter)

    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    file_handler.setFormatter(file_formatter)
    logger.addHandler (console_handler)
    logger.addHandler(file_handler)
    return logger

def get_inventory(yaml_file):
    cmd = ["eac", "deployment", "inventory", "-f", yaml_file, "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Inventory command failed: {result.stderr}")
    return json.loads(result.stdout)
#
#
# Deduplicate Resources
def deduplicate_resources(resources):
    seen = set()
    unique = []
    for r in resources:
        arn = r.get("arn")
        if arn and arn not in seen: 
            seen.add(arn)
            unique.append(r)
    return unique

def check_rds_aurora_health(cluster_name):
    rds = boto3.client('rds')
    try:
        cluster_info = rds.describe_db_clusters(DBClusterIdentifier=cluster_name)
        cluster_status = cluster_info['DBClusters'][0]['Status']

        if cluster_status != 'available':
            return False, f"cluster {cluster_name} status: {cluster_status}"

        # Check instances in cluster
        instance_ids = [inst['DBInstanceldentifier'] for inst in cluster_info['DBClusters'][0]['DBClusterMembers']]
        failed instances = []
        for inst_id in instance_ids:
            inst_info = rds.describe_db_instances(DBInstanceIdentifier=inst_id)
            inst_status = inst_info['DBInstances'][0]['DBInstanceStatus']
            if inst_status != 'available':
                failed_instances.append(f"{inst_td} status: {Inst_status}")

        if failed_instances:
            return False, failed_instances
        return True, None
    except ClientError as e:
        return False, f"AWS API error:{str(e)}"
    except Exception as e:
        return False, f"Error checking cluster {cluster_name}: {str(e)}"


def main(yaml_file, log_file):
    inventory = get_inventory(yaml_file)
    failed_components = []
    
    for resource in inventory.get("resources", []):
        arn = resource.get("arn")
        if arn and "rds" in arn and "cluster" in arn:
            healthy, details = check_rds_aurora_health(arn)
            if not healthy:
                failed_components.append({arn: details})
    
    if failed_components:
        result = f"Failure: Unhealthy components:\n{json.dumps(failed _components, indent=2)}"
        print(result)
        write_output_to_file(result, output_file)
        sys.exit(1)
    else:
        result = "Success: All Aurora clusters healthy"
        print(result)
        write_output_to_file(result, output_file)
        sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python health_check-py <deployment_example.yaml> <output_file>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])