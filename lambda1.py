import asyncio
from typing import List
from core.base_checker_async import AsyncBaseChecker
from core.models import HealthCheckResult
from utils.cloudwatch_async import get_metric_async

class AsyncLambdaChecker(AsyncBaseChecker):

    def _init_(self, lambda_client, cw_client):
        self.lambda_client = lambda_client
        self.cw_client = cw_client

    async def check_availability(self) -> List[HealthCheckResult]:
        response = await self.lambda_client.list_functions()
        functions = response["Functions"]

        results = []
        for fn in functions:
            state = fn.get("State", "Unknown")
            status = "OK" if state == "Active" else "CRITICAL"

            results.append(
                HealthCheckResult(
                    service="Lambda",
                    resource_id=fn["FunctionName"],
                    status=status,
                    details={"state": state}
                )
            )
        return results

    async def _check_single_function_perf(self, fn):
        errors = await get_metric_async(
            self.cw_client,
            "AWS/Lambda",
            "Errors",
            "FunctionName",
            fn["FunctionName"]
        )

        status = "OK" if errors == 0 else "WARNING"

        return HealthCheckResult(
            service="Lambda",
            resource_id=fn["FunctionName"],
            status=status,
            details={"errors_last_5min": errors}
        )

    async def check_performance(self) -> List[HealthCheckResult]:
        response = await self.lambda_client.list_functions()
        functions = response["Functions"]

        tasks = [
            self._check_single_function_perf(fn)
            for fn in functions
        ]

        return await asyncio.gather(*tasks)

    async def check_configuration(self) -> List[HealthCheckResult]:
        response = await self.lambda_client.list_functions()
        functions = response["Functions"]

        results = []
        for fn in functions:
            timeout = fn["Timeout"]

            if timeout > 900:
                status = "CRITICAL"
            elif timeout > 600:
                status = "WARNING"
            else:
                status = "OK"

            results.append(
                HealthCheckResult(
                    service="Lambda",
                    resource_id=fn["FunctionName"],
                    status=status,
                    details={"timeout": timeout}
                )
            )
        return results