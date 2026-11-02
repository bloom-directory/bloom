"""Use the OpenCode binary already pinned by the shared agent image."""

from harbor.agents.installed.opencode import OpenCode


class ImageOpenCode(OpenCode):
    async def install(self, environment):
        # Harbor's default installer downloads NVM and OpenCode on every run.
        # The shared image already contains Node and the selected CLI.
        await self.exec_as_agent(environment, command="opencode --version")

    def get_version_command(self):
        return "opencode --version"
