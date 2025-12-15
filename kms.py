from typing import List
from core.base_checker_async import AsyncBaseChecker
from core.models import HealthCheckResult

class AsyncKMSChecker(AsyncBaseChecker):

    def _init_(self, kms_client):
        self.kms_client = kms_client

    async def check_availability(self) -> List[HealthCheckResult]:
        keys = (await self.kms_client.list_keys())["Keys"]
        results = []

        for key in keys:
            meta = (
                await self.kms_client.describe_key(KeyId=key["KeyId"])
            )["KeyMetadata"]

            status = "OK" if meta["Enabled"] else "CRITICAL"

            results.append(
                HealthCheckResult(
                    service="KMS",
                    resource_id=key["KeyId"],
                    status=status,
                    details={"enabled": meta["Enabled"]}
                )
            )
        return results

    async def check_configuration(self) -> List[HealthCheckResult]:
        keys = (await self.kms_client.list_keys())["Keys"]
        results = []

        for key in keys:
            rotation = (
                await self.kms_client.get_key_rotation_status(KeyId=key["KeyId"])
            )["KeyRotationEnabled"]

            status = "OK" if rotation else "WARNING"

            results.append(
                HealthCheckResult(
                    service="KMS",
                    resource_id=key["KeyId"],
                    status=status,
                    details={"rotation_enabled": rotation}
                )
            )
        return results

    async def check_performance(self):
        return []