import { readFileSync } from "node:fs";
import hardhatEthers from "@nomicfoundation/hardhat-ethers";
import hardhatIgnition from "@nomicfoundation/hardhat-ignition-ethers";
// rpc.json is the local adapter's output. It contains an ephemeral submission
// URL, not a wallet signing key. Keep it private and out of version control.
const { rpc_url } = JSON.parse(readFileSync("rpc.json", "utf8"));
export default {
  plugins: [hardhatEthers, hardhatIgnition],
  solidity: "0.8.28",
  networks: {
    bloom: { type: "http", chainType: "l1", url: rpc_url, accounts: "remote", timeout: 180_000 },
  },
  ignition: { requiredConfirmations: 1 },
};
