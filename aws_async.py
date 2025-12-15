import aioboto3
from contextlib import asynccontextmanager

class AsyncAWSSession:
    def _init_(self, region: str, profile: str = None):
        self.region = region
        self.profile = profile

    @asynccontextmanager
    async def client(self, service_name: str):
        session = aioboto3.Session(profile_name=self.profile)
        async with session.client(
            service_name,
            region_name=self.region
        ) as client:
            yield client