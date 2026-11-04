"""Use the OpenCode binary already pinned by the shared agent image."""

import shlex

from harbor.agents.installed.opencode import OpenCode

# Harbor points OpenCode's XDG_DATA_HOME into the logged agent directory, so
# the login lives outside it and only a link sits there, removed after the run.
SECRET_AUTH = "/tmp/opencode-secrets/auth.json"
LOGGED_AUTH = "/logs/agent/opencode/xdg-data/opencode/auth.json"


class ImageOpenCode(OpenCode):
    async def install(self, environment):
        # Harbor's default installer downloads NVM and OpenCode on every run.
        # The shared image already contains Node and the selected CLI.
        await self.exec_as_agent(environment, command="opencode --version")

    def get_version_command(self):
        return "opencode --version"

    async def run(self, instruction, environment, context):
        auth = self._get_env("OPENCODE_AUTH_JSON_PATH")
        if not auth:
            return await super().run(instruction, environment, context)
        await self.exec_as_root(environment, command="mkdir -p /tmp/opencode-secrets")
        await environment.upload_file(auth, SECRET_AUTH)
        if environment.default_user is not None:
            await self.exec_as_root(
                environment,
                command=f"chown -R {environment.default_user} /tmp/opencode-secrets",
            )
        link = shlex.quote(LOGGED_AUTH)
        await self.exec_as_agent(
            environment,
            command=f"mkdir -p $(dirname {link}) && ln -sf {SECRET_AUTH} {link}",
        )
        try:
            await super().run(instruction, environment, context)
        finally:
            await self.exec_as_agent(environment, command=f"rm -f {link}")
