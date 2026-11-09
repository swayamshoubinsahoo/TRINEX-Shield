require("@nomicfoundation/hardhat-toolbox");
const pk = process.env.PRIVATE_KEY;
module.exports = {
  solidity: "0.8.24",
  networks: {
    sepolia: { url: process.env.SEPOLIA_RPC || "https://ethereum-sepolia-rpc.publicnode.com", accounts: pk ? [pk] : [] },
    arbitrumSepolia: { url: process.env.ARB_RPC || "https://sepolia-rollup.arbitrum.io/rpc", accounts: pk ? [pk] : [] }
  }
};
