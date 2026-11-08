"""Run Pi with the OAuth login named by PI_AUTH_JSON_PATH."""

from harbor.agents.installed.pi import Pi

SECRET_AUTH = "/tmp/pi-secrets/auth.json"


class ImagePi(Pi):
    async def run(self, instruction, environment, context):
        auth = self._get_env("PI_AUTH_JSON_PATH")
        if auth:
            await self.exec_as_root(environment, command="mkdir -p /tmp/pi-secrets")
            await environment.upload_file(auth, SECRET_AUTH)
            if environment.default_user is not None:
                await self.exec_as_root(
                    environment,
                    command=f"chown -R {environment.default_user} /tmp/pi-secrets",
                )
            # Pi reads ~/.pi/agent/auth.json, outside the logged directories.
            await self.exec_as_agent(
                environment,
                command=f"mkdir -p ~/.pi/agent && ln -sf {SECRET_AUTH} ~/.pi/agent/auth.json",
            )
        await super().run(instruction, environment, context)
