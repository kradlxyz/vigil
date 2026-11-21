# Vigil

2-second on-chain smart contract & bytecode safety scanner for **Base Mainnet (`8453`)** and **Robinhood Chain Mainnet (`4663`)**, with a free bot-ready REST API and built-in Telegram Bot.

- **Live App:** https://scan.kradl.xyz
- **REST API:** `GET https://scan.kradl.xyz/api/scan/{chainId}/{address}`

## What Vigil Checks On-Chain
- **Sourcify v2 Verification:** Live `exact_match` / `match` / `Unverified` status.
- **Upgradeable Proxy Detection:** EIP-1967 implementation storage slot & EIP-1167 minimal proxy clone detection.
- **Bytecode 4-Byte Selector Audit:** Scans `PUSH4` opcodes for `mint`, `pause`, `blacklist`, `setBlacklist`, `setFee`, `upgradeTo`, and `upgradeToAndCall`.
- **Ownership & ERC-20 Metadata:** Live `owner()` renouncement check plus `name`, `symbol`, `decimals`, `totalSupply`, ETH balance, and bytecode size.
- **Telegram Bot Ready:** Set `TELEGRAM_BOT_TOKEN` to enable `/scan base 0x...` or `/scan robinhood 0x...` in any chat or group.

## Local Development
```bash
npm install
npm test
npm run dev
```
