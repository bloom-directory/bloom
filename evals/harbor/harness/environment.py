"""Keep Harbor's host-file ownership repair out of the live Bloom namespace."""

from harbor.environments.docker.docker import DockerEnvironment


class BloomDockerEnvironment(DockerEnvironment):
    async def _chown_to_host_user(self, path, recursive=False, service=None):
        if path == "/bloom" or path.startswith("/bloom/"):
            # These are virtual projections and command routes, not host files.
            return
        await super()._chown_to_host_user(path, recursive, service)
