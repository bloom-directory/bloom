import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
export default buildModule("BloomDeployment", (m) => {
  const box = m.contract("DeploymentBox", [7], { value: 123n });
  const registry = m.contract("DeploymentRegistry", [box]);
  m.call(box, "set", [9]);
  return { box, registry };
});
