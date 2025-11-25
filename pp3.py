import subprocess
import json
import yaml
import boto3
import sys
import os

def load_yaml(file_path):
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)

def get_inventory(file_path):
    cmd = ["eac", "deployment", "inventory", "-f", file_path, "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("Error running inventory command:", result. stderr)
        sys.exit(1)
    return json.loads(result.stdout)

def check_rds_aurora_health(cluster_name):
    rds = boto3.client('rds')
    try:
        cluster_info = rds.describe_db_clusters(DBClusterIdentifier=cluster_name)
        cluster_status = cluster_info['DBClusters'][0]['Status']
        if cluster_status != 'available':
            return False, f"Cluster {cluster_name} status: {cluster_status}"

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
    except Exception as e:
        return False, f"Error checking cluster {cluster_name}: {str(e)}"

def write_output_to_file(output, file_path):
    try:
        with open(file_path, 'w') as f:
            f.write(output)
        print(f"\n output written to file: {file_path}")
    except Exception as e:
        print(f"\n failed to write output to file: {e}")

def main(yaml_file, output_file):
    inventory = get_inventory(yaml_file)
    failed_components = []
    
    for resource in inventory.get("resources", []):
        if resource.get("type") == "RDSAuroraPostgres":
            cluster_name = resource.get("name")
            healthy, details = check_rds_aurora_health(cluster_name)
            if not healthy:
                failed_components.append({cluster_name: details})
    
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