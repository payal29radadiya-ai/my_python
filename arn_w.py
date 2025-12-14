#!/usr/bin/env python3
# AWS Health Check Utility - ARN or Inventory
#- Checks health for various AWS resources identified by ARN.
#- Supports checking a single --arn, a JSON inventory (-inventory-json), or invoking an external command
#that prints JSON with an "arns" list (eg., eac deployment inventory <yaml> -json).
# - Includes special handling for AWS Backup ARNs that wrap RDS cluster/db snapshots.
#
# Requirements:
# pip install boto3
# AWS credentials configured via env vars, profile, or instance role.
import argparse
import json
import logging
import sys
import csv
import re
import subprocess
from typing import Dict, List, Tuple, Optional
#----------------------Logging Setup-------------------------------
def setup_logging(log_file: str) -> None:
    logging.basicConfig{
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            Logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, encoding='utf-8')
        ]
    }

#---------------ARN Parsing---------------------
ARN_RE = re.compile(r"^arn:(?P<partition>aws|aws-us-gov|aws-cn):(?P<service>[a-z0-9-]+):(?P<region>[a-z0-9-]*):(?P<account>]*):(?P<resource>.+)$")

def parse_arn(arn: str) -> Optional[Dict[str, str]]:
    m = ARN_RE.match(arn)
    if not m:
        return None
    d = m.groupdict()
    d['region'] = d['region'] or None
    d['account'] = d['account'] or None
    return d

def resource_parts( resource: str) - Tuplelstr, strl:
    """Split resource into type and id/name using common ARN forms.
    Examples:
    - instance/1-01234' →> ('instance', 'i-01234')
    - 'cluster aurora-prod' → ('cluster', 'aurora-prod*)
    - ' role/SomeRole' → ('role', 'SomeRale')
    - 'loadbalancer/app/my-alb/12345' → ('loadbalancer', 'app/my-alb/12345' )
    - 'cluster-snapshot: rds:my-cluster-snap' →> ('cluster-snapshot', 'rds:my-cluster-snap')
    """

    if '/' in resource:
        t, rest = resource.split('/', 1)
        return t, rest 
    if ':' in resource:
        t, rest = resource-split(':', 1)
        return t, rest 
    return 'unknown', resource


def get_boto3_client(service: str, region: Optional[str], default_region: Optional[str]):
    import boto3
    from botocore.config import Config
    cfg = Config(retries={'max_attempts': 5, 'mode': 'standard'})
    region_to_use = region or default_region
    # Global services can work without explicit region, but we allow a default.
    if service in ('iam', 'route53'):
        return boto.client(service, config=cfg, region_name=region_to_use)
    if not region_to_use:
        raise ValueError(f"Region required for service {service}; provide -default-region if missing in ARN.")
    return boto3.client(service, region_name=region_to_use, config=cfg)

def check_lambda_function(arn_info: Dict[str,str], default_region: Optional[str]) -> Dict:
    service = 'lamda'
    client = get_boto3_client(service, arn_info['region'], default_region)
    rtype, rid = resource_parts(arn_info['resources'])
    rtype, rid = resource_parts(arn_infol' resource'])
    try:
        if rtype = 'function':
            func_arn = f"arn:{arn _info['partition']}:{arn_info['service']}:{amn_info['region']}:{arn_info['account']}:function:{rid}"
            conf = client.get_function_configuration(FunctionName=func_arn)
            last_update = conf.get('LastUpdateStatus')
            ok = last_update == 'Successful'
            return {"status", "OK" if ok else "FAIL", "detail": f"lastUpdateStatus={last_update}", "metadata": {"functionName": conf.get('Functioname')}} 
        else:
            return {"status": "UNKNOWN", "detail": f"Unsupported Lambda resources: {arn_info['resource']}"}
    except Exception as e:
        return {"status": "ERROR", "detail": str(e)}


SERVICE_CHECKS = {
    'lamda': check_lambda_function,
}

# ------------------------------------------------------
# Run Inventory Command
# ------------------------------------------------------
def run_inventory_cmd(eac_command: str, yaml_path: str) -> Dict:
    logger.info(f"Running EAC inventory for file: {yaml_file}")
    cmd = f"{eac_command} {yaml_path} --json"
    logger.info(f"Running inventory command: {cmd}")
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if proc.return != 0:
        raise RuntimeError(f"Inventory command failed: {proc.stderr}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        try:
            return json.loads(proc.stderr)
        except Exception"
            raise


def load_inventory_json(path: str) -> Dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def write_json_report(rows: List[Dict], path: str) -> None: 
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(rows, f, indent=2)

def write_csv_report(rows: List[Dict], path: str) -> None:
    fieldnames = ['arn', 'service', 'region', 'status', 'detail']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.Dictwriter(f, fieldnames=fieldnames)
        w.writeheader ()
        for r in rows:
            w.writerow({k: r.get(k) for k in fieldnames})


def main():
    parser = argparse.ArgumentParser(description='AWS Health Check Utility (single ARN or inventory)')
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument ('—-arn', help='Single ARN to check')
    src.add_argument('-inventory-json', help='Path to JSON returned by inventory (contains "arns" list)')
    src.add_argument('—-yaml', help='Path to deployment.yaml to run inventory against')
    parser.add_argument('--inventory-command', default='eac deployment inventory', help='Inventory CLI to call when using --yaml') 
    parser.add_argument('--default-region', help='Fallback region for global ARNs or when region is missing (e.g., us-east-1)')
    parser.add_argument('-—log-file', default='aws_healthcheck.log', help='Path to log file')
    parser.add_argument('--out-json', default='health_report.json', help='Path for JSON report output')
    parser.add_argument('--out-csv', default='health_report.csv', help='Path for CSV report output')
    
    args = parser.parse_args()
    setup_logging(args.log_file)
    # Build ARN list
    if args.arn:
        arns = [args.arn.strip()]
        inv = {"arns": arns}
    elif args.inventory_json:
        inv = load_inventory_ json(args.inventory_json)
        arns = inv.get('arns'; [])
    else:
        inv = run_inventory_command(args.inventory_command, args.yaml)
        arns = inv.get('arns', [])

    if not isinstance(arns, list) or not arns:
        logging.error( 'No ARNs found to check. Aborting.')
        sys.exit(2)

    seen = set()
    unique_arns = []
    for a in arns:
        if a not in seen:
            unique_arns.append(a)
            seen.add(a)
    logging.info(f"Found {len(unique_arns)} unique ARNs")

    results = []
    any_fail = False
    for arn in unique_arns:
        info = parse_arn(arn)
        if not info:
            logging.warning(f"Skipping invalid ARN: {arn}")
            results.append({"arn": arn, "service"; "unknown", "region": None, "status": "INVALID", "detail": "Not an ARN"})
            any_fail = True
            continue
        service = info['service']
        checker = SERVICE_CHECKS.get(service)
        if not checker:
            detail = f"No health check implemented for service '{service}"
            logging.info(f"{arn} -> {detail}")
            results-append ({"arn": arn, "service": service, "region"= info['region'], "status": "SKIPPED", "detail": detail})
            continue
        
        logging.info(f"Checking {service} health for ARNE {arn}")
        r = checker(info, args.default_region)
        status = r.get('status', 'UNKNOWN')
        detail = r.get('detail', '')
        if status in ('FAIL', 'ERROR', 'INVALID'):
            any_fail = True 
        results.append ({
            "arn": arn,
            "service": service,
            "region": info['region'],
            "status": status,
            "detail": detail
        })

    
    # Write reports
    write_json_report(results, args.out_json)
    write_csv_report(results, args.out_csv)
    
    # Pretty print summary
    print("\n=== AWS Health Check Summary ==")
    for r in results:
        region = r['region'] if r['region'] else '-'
        print(f"{r['status']:>7} | {r['service']:<24} | {region:<12} | {r['arn']}")
    print(f"\nWrote JSON report: {args.out_json}")
    print(f"Wrote CSV report : (args.out_csv)")
    sys.exit(1 if any_fail else 0)

if __name__ == '__main__':
    main()