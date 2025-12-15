from typing import List
from core.base_checker_async import AsyncBaseChecker
from core.models import HealthCheckResult

class AsyncNLBChecker(AsyncBaseChecker):

    def _init_(self, elbv2_client):
        self.elbv2_client = elbv2_client

    async def check_availability(self) -> List[HealthCheckResult]:
        lbs = (await self.elbv2_client.describe_load_balancers())["LoadBalancers"]

        results = []
        for lb in lbs:
            if lb["Type"] != "network":
                continue

            state = lb["State"]["Code"]
            status = "OK" if state == "active" else "CRITICAL"

            results.append(
                HealthCheckResult(
                    service="NLB",
                    resource_id=lb["LoadBalancerName"],
                    status=status,
                    details={"state": state}
                )
            )
        return results

    async def check_configuration(self) -> List[HealthCheckResult]:
        lbs = (await self.elbv2_client.describe_load_balancers())["LoadBalancers"]

        results = []
        for lb in lbs:
            if lb["Type"] != "network":
                continue

            attrs = (
                await self.elbv2_client.describe_load_balancer_attributes(
                    LoadBalancerArn=lb["LoadBalancerArn"]
                )
            )["Attributes"]

            cross_zone = next(
                (a["Value"] for a in attrs if a["Key"] == "load_balancing.cross_zone.enabled"),
                "false"
            )

            status = "OK" if cross_zone == "true" else "WARNING"

            results.append(
                HealthCheckResult(
                    service="NLB",
                    resource_id=lb["LoadBalancerName"],
                    status=status,
                    details={"cross_zone_enabled": cross_zone}
                )
            )
        return results

    async def check_performance(self):
        return []