# TRINEX Shield
AI-assisted web threat detection + TLS trust analysis + on-chain report registry.
## Run
1. `npm i -D hardhat@2 @nomicfoundation/hardhat-toolbox@hh2` then `npx hardhat node` (terminal 1)
2. `npx hardhat run scripts/deploy.js --network localhost` (terminal 2)
3. `cd backend && pip install -r requirements.txt && uvicorn main:app --reload` (optional: set ANTHROPIC_API_KEY)
4. Open http://127.0.0.1:8000

## Public testnet (optional)
1. Create a throwaway wallet and fund it with Sepolia test ETH from a faucet. Never use a real wallet.
2. `export PRIVATE_KEY=0xYOUR_TESTNET_KEY` then `npx hardhat run scripts/deploy.js --network sepolia`
3. `export RPC=https://ethereum-sepolia-rpc.publicnode.com PRIVATE_KEY=0xYOUR_TESTNET_KEY` and start uvicorn.
4. Register a report: the receipt shows a "View on block explorer" link.
Do not commit keys to GitHub.

## Browser extension
See `extension/README.md`.

## Safety and privacy design (maps to brief section 9)
- SSRF protection: every redirect hop is resolved and internal addresses are blocked. Timeouts and size caps apply.
- No script execution: pages are never rendered. Only the first 150 KB of HTML text is read for static analysis and nothing is saved.
- AI safety: page and message text is treated as untrusted data in the prompt, and evidence is required. Only the risk label and finding labels are sent to the AI. Extracted phone numbers, emails and UPI ids stay on the server.
- Blockchain: only a SHA-256 hash is stored. Raw URLs and message content stay off-chain.
- Known gap: inspection runs on the host, not in a sandbox. Production use would run it in an isolated container.
