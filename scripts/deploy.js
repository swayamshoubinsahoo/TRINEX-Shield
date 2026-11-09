const fs = require("fs");
async function main() {
  const c = await (await ethers.getContractFactory("ThreatRegistry")).deploy();
  await c.waitForDeployment();
  const address = await c.getAddress();
  fs.writeFileSync("backend/deployed.json", JSON.stringify({ address }));
  console.log("ThreatRegistry deployed at:", address);
}
main().catch(e => { console.error(e); process.exit(1); });
