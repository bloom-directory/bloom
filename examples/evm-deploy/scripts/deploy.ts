import { network } from "hardhat";
import { NonceManager } from "ethers";
const { ethers } = await network.create();
// Explicit nonces let Bloom recognize retries without conflating two equal calls.
const sender = new NonceManager((await ethers.getSigners())[0]);
const Box = await ethers.getContractFactory("DeploymentBox", sender);
const box = await Box.deploy(7, { value: 123 });
await box.waitForDeployment();
const Registry = await ethers.getContractFactory("DeploymentRegistry", sender);
const registry = await Registry.deploy(await box.getAddress());
await registry.waitForDeployment();
await (await box.set(9)).wait();
if (await box.value() !== 9n) throw new Error("initialization failed");
console.log(JSON.stringify({ box: await box.getAddress(), registry: await registry.getAddress() }));
