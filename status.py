import subprocess
import json
import boto3
import sys
import logging

def run_command(command):
    """Run a shell command and return the output as a string."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running command: {e}")
        sys.exit(1)

def get_inventory_json(yaml_file):
    """Generate inventory JSON using the eac command."""
    command = f"eac deployment inventory -f {yaml_file} --json"
    output = run_command(command)
    return json.loads(output)

def check_arn_health(arn, region, account_id):
    """Generalized health check for ARN based on service."""
    # Parse ARN: arn:aws:service:region:account:resource
    parts = arn.split(':')
    if len(parts) < 6:
        return False, "Invalid ARN format"
    service = parts[2]
    resource = ':'.join(parts[5:])
    
    client = boto3.client(service, region_name=region)
    
    try:
        if service == 'lambda':
            function_name = resource.split(':')[-1]
            response = client.get_function(FunctionName=function_name)
            state = response['Configuration']['State']
            return state == 'Active', f"State: {state}"
        elif service == 'ecs':
            # Assume cluster
            cluster_name = resource.split('/')[-1]
            response = client.describe_clusters(clusters=[cluster_name])
            if response['clusters']:
                status = response['clusters'][0]['status']
                return status == 'ACTIVE', f"Status: {status}"
            return False, "Cluster not found"
        elif service == 'kms':
            key_id = resource.split('/')[-1]
            response = client.describe_key(KeyId=key_id)
            enabled = response['KeyMetadata']['Enabled']
            return enabled, f"Enabled: {enabled}"
        elif service == 'sqs':
            queue_name = resource
            queue_url = f"https://sqs.{region}.amazonaws.com/{account_id}/{queue_name}"
            client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])
            return True, "Exists"
        elif service == 'backup':
            # For recovery-point
            recovery_point_arn = arn
            vault_name = resource.split(':')[1]  # Extract vault name from resource part
            response = client.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=recovery_point_arn)
            status = response['Status']
            return status == 'COMPLETED', f"Status: {status}"
        elif service == 'ec2':
            if 'security-group' in resource:
                sg_id = resource.split('/')[-1]
                response = client.describe_security_groups(GroupIds=[sg_id])
                return True, "Exists"
            else:
                return False, "Unsupported EC2 resource"
        elif service == 'rds':
            if 'cluster-snapshot' in resource:
                snapshot_id = resource.split(':')[-1]
                response = client.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshot_id)
                status = response['DBClusterSnapshots'][0]['Status']
                return status == 'available', f"Status: {status}"
            else:
                return False, "Unsupported RDS resource"
        else:
            return False, f"Unsupported service: {service}"
    except Exception as e:
        return False, f"Error: {str(e)}"

def main(yaml_file):
    # Configure logging to write to a file
    logging.basicConfig(filename='health_check.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    logging.info("Starting health check for deployment inventory.")
    
    # Get inventory JSON
    inventory = get_inventory_json(yaml_file)
    
    # Extract environment details
    deployment = inventory.get('data', {}).get('deployment', {})
    environment = deployment.get('Environment', {})
    region = environment.get('awsRegion', 'us-east-1')  # Default if not present
    account_id = environment.get('awsAccountID', '')
    
    all_healthy = True
    messages = []
    arn_results = []
    
    # Process components dynamically from the JSON
    components = deployment.get('components', [])
    for component in components:
        component_type = component.get('componentType', '')
        component_name = component.get('componentName', '')
        tf_modules = component.get('tfModules', [])
        for tf_module in tf_modules:
            arns_list = tf_module.get('arns', [])  # List of ARN strings
            updated_arns = []
            for arn in arns_list:
                # ARN is a string, perform health check
                healthy, message = check_arn_health(arn, region, account_id)
                if not healthy:
                    all_healthy = False
                messages.append(f"{arn} ({component_name}, {component_type}): {message}")
                
                # Create a dict for each ARN with health info
                arn_dict = {
                    "arn": arn,
                    "status": "healthy" if healthy else "unhealthy",
                    "message": message
                }
                updated_arns.append(arn_dict)
                arn_results.append({
                    "arn": arn,
                    "componentName": component_name,
                    "componentType": component_type,
                    "status": "healthy" if healthy else "unhealthy",
                    "message": message
                })
                logging.info(f"Checked {arn} ({component_name}, {component_type}): {'healthy' if healthy else 'unhealthy'} - {message}")
            # Update the tf_module's arns with health info
            tf_module['arns'] = updated_arns
    
    # Prepare output in the specified format
    status = "SUCCESS" if all_healthy else "FAILURE"
    message = "; ".join(messages) if messages else "All ARNs are healthy"
    
    output = {
        "status": status,
        "message": message,
        "data": {
            "deployment": deployment,  # Updated with health info in arns
            "arnResults": arn_results  # Additional list for easy access
        }
    }
    
    # Output results as JSON to CLI (stdout) and log it
    output_json = json.dumps(output, indent=2)
    print(output_json)  # Print to CLI
    logging.info(f"Health check completed. Status: {status}. Results: {output_json}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <deployment.yaml>")
        sys.exit(1)
    yaml_file = sys.argv[1]
    main(yaml_file)
