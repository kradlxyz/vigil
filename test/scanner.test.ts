import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { inspectBytecode, computeSafetyScore } from "../src/scanner.js";
import { formatTelegramReport } from "../src/bot.js";

describe("Vigil bytecode inspection & scoring", () => {
  it("detects EIP-1167 minimal proxy and target address", () => {
    const target = "1111111111111111111111111111111111111111";
    const bytecode = `0x363d3d373d3d3d363d73${target}5af43d82803e903d91602b57fd5bf3`;
    const res = inspectBytecode(bytecode);
    assert.equal(res.isMinimalProxy, true);
    assert.equal(res.minimalProxyTarget, `0x${target}`);
    assert.equal(res.sizeBytes, 45);
  });

  it("detects high-risk PUSH4 admin selectors (mint, blacklist, pause, owner)", () => {
    // PUSH4 40c10f19 (mint), PUSH4 44337ea1 (blacklist), PUSH4 8da5cb5b (owner)
    const bytecode = "0x60806040526340c10f196344337ea1638da5cb5b00";
    const res = inspectBytecode(bytecode);
    const names = res.matchedSelectors.map((s) => s.name);
    assert.ok(names.includes("mint(address,uint256)"));
    assert.ok(names.includes("blacklist(address)"));
    assert.equal(res.hasOwnerSelector, true);
  });

  it("scores verified immutable contract with zero risky selectors at 100 (LOW RISK)", () => {
    const res = computeSafetyScore({
      isContract: true,
      sourcifyVerified: true,
      isProxy: false,
      hasOwnerFn: false,
      ownerRenounced: false,
      matchedSelectors: [],
    });
    assert.equal(res.score, 100);
    assert.equal(res.riskLevel, "LOW RISK");
  });

  it("penalizes unverified proxy with mint + blacklist into HIGH RISK", () => {
    const inspected = inspectBytecode("0x6340c10f196344337ea1638da5cb5b");
    const res = computeSafetyScore({
      isContract: true,
      sourcifyVerified: false,
      isProxy: true,
      hasOwnerFn: true,
      ownerRenounced: false,
      matchedSelectors: inspected.matchedSelectors,
    });
    assert.equal(res.riskLevel, "HIGH RISK");
    assert.ok(res.score <= 25);
  });

  it("formats Telegram report cleanly with score and share link", () => {
    const msg = formatTelegramReport(
      {
        chainId: 8453,
        chainName: "Base Mainnet",
        address: "0x2FEE1b921F68A19bFdA0B587dff8bC245727D518",
        explorerUrl: "https://basescan.org/address/0x2FEE1b921F68A19bFdA0B587dff8bC245727D518",
        scannedAt: new Date().toISOString(),
        isContract: true,
        bytecodeSizeBytes: 12000,
        ethBalance: "0.5",
        txCount: 1,
        sourcify: { verified: true, matchType: "exact_match", contractName: "KradlLaunchpad", compiler: "0.8.24" },
        proxy: { isProxy: false, type: null, implementation: null },
        ownership: { hasOwnerFn: true, ownerAddress: "0x842EB2283717E08CCa125dD33B364D4fD9Dea85d", renounced: false },
        token: { isErc20: false, name: null, symbol: null, decimals: null, totalSupplyFormatted: null },
        detectedSelectors: [],
        score: 90,
        riskLevel: "LOW RISK",
        checks: [{ id: "sourcify", label: "Sourcify", status: "pass", detail: "Verified" }],
      },
      "https://scan.kradl.xyz"
    );
    assert.ok(msg.includes("90/100"));
    assert.ok(msg.includes("https://scan.kradl.xyz/?chain=8453"));
  });
});
