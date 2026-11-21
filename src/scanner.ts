import { createPublicClient, http, formatEther, formatUnits, parseAbi, isAddress } from "viem";

export interface ChainDef {
  id: number;
  name: string;
  shortName: string;
  rpcUrl: string;
  explorerUrl: string;
}

export const SUPPORTED_CHAINS: Record<number, ChainDef> = {
  8453: {
    id: 8453,
    name: "Base Mainnet",
    shortName: "Base",
    rpcUrl: process.env.BASE_RPC_URL || "https://base-rpc.publicnode.com",
    explorerUrl: "https://basescan.org",
  },
  4663: {
    id: 4663,
    name: "Robinhood Chain Mainnet",
    shortName: "Robinhood",
    rpcUrl: process.env.ROBINHOOD_RPC_URL || "https://robinhood-rpc.publicnode.com",
    explorerUrl: "https://robinhoodchain.blockscout.com",
  },
};

export interface SafetyCheck {
  id: string;
  label: string;
  status: "pass" | "warn" | "fail" | "info";
  detail: string;
}

export interface ScanReport {
  chainId: number;
  chainName: string;
  address: `0x${string}`;
  explorerUrl: string;
  scannedAt: string;
  isContract: boolean;
  bytecodeSizeBytes: number;
  ethBalance: string;
  txCount: number;
  sourcify: {
    verified: boolean;
    matchType: "exact_match" | "match" | "unverified";
    contractName: string | null;
    compiler: string | null;
  };
  proxy: {
    isProxy: boolean;
    type: "EIP-1967" | "EIP-1167" | null;
    implementation: string | null;
  };
  ownership: {
    hasOwnerFn: boolean;
    ownerAddress: string | null;
    renounced: boolean;
  };
  token: {
    isErc20: boolean;
    name: string | null;
    symbol: string | null;
    decimals: number | null;
    totalSupplyFormatted: string | null;
  };
  detectedSelectors: string[];
  score: number;
  riskLevel: "LOW RISK" | "MEDIUM RISK" | "HIGH RISK";
  checks: SafetyCheck[];
}

// EIP-1967 implementation slot: bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
const EIP1967_IMPL_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as const;

const ERC20_ABI = parseAbi([
  "function name() view returns (string)",
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "function totalSupply() view returns (uint256)",
  "function owner() view returns (address)",
]);

const RISK_SELECTORS: Array<{
  selector: string;
  name: string;
  severity: "warn" | "fail";
  penalty: number;
  description: string;
}> = [
  {
    selector: "40c10f19",
    name: "mint(address,uint256)",
    severity: "fail",
    penalty: 20,
    description: "Public/admin mint selector present in bytecode",
  },
  {
    selector: "8456cb59",
    name: "pause()",
    severity: "warn",
    penalty: 10,
    description: "Contract contains pause() selector (transfers/actions may be haltable)",
  },
  {
    selector: "44337ea1",
    name: "blacklist(address)",
    severity: "fail",
    penalty: 20,
    description: "Blacklist selector detected in bytecode",
  },
  {
    selector: "153b0d1e",
    name: "setBlacklist(address,bool)",
    severity: "fail",
    penalty: 20,
    description: "Blacklist setter selector detected in bytecode",
  },
  {
    selector: "69fe0e2d",
    name: "setFee(uint256)",
    severity: "warn",
    penalty: 12,
    description: "Mutable fee selector detected in bytecode",
  },
  {
    selector: "3659cfe6",
    name: "upgradeTo(address)",
    severity: "warn",
    penalty: 15,
    description: "UUPS upgradeTo(address) selector detected",
  },
  {
    selector: "4f1ef286",
    name: "upgradeToAndCall(address,bytes)",
    severity: "warn",
    penalty: 15,
    description: "UUPS upgradeToAndCall selector detected",
  },
];

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const DEAD_ADDRESS = "0x000000000000000000000000000000000000dead";

/**
 * Pure bytecode inspection helper (unit-testable without RPC).
 * Scans PUSH4 (0x63) 4-byte selectors and EIP-1167 minimal proxy prefix.
 */
export function inspectBytecode(bytecodeHex: string): {
  sizeBytes: number;
  isMinimalProxy: boolean;
  minimalProxyTarget: string | null;
  matchedSelectors: typeof RISK_SELECTORS;
  hasOwnerSelector: boolean;
} {
  const clean = bytecodeHex.startsWith("0x") ? bytecodeHex.slice(2).toLowerCase() : bytecodeHex.toLowerCase();
  const sizeBytes = Math.floor(clean.length / 2);

  // EIP-1167 minimal proxy: 363d3d373d3d3d363d73<20-byte-address>5af43d82803e903d91602b57fd5bf3
  const isMinimalProxy = clean.startsWith("363d3d373d3d3d363d73") && clean.length >= 60;
  const minimalProxyTarget = isMinimalProxy ? `0x${clean.slice(20, 60)}` : null;

  // Match PUSH4 <4-byte selector> (0x63 followed by 8 hex chars)
  const matchedSelectors = RISK_SELECTORS.filter((r) => clean.includes(`63${r.selector}`));
  const hasOwnerSelector = clean.includes("638da5cb5b");

  return {
    sizeBytes,
    isMinimalProxy,
    minimalProxyTarget,
    matchedSelectors,
    hasOwnerSelector,
  };
}

export function computeSafetyScore(params: {
  isContract: boolean;
  sourcifyVerified: boolean;
  isProxy: boolean;
  hasOwnerFn: boolean;
  ownerRenounced: boolean;
  matchedSelectors: typeof RISK_SELECTORS;
}): { score: number; riskLevel: "LOW RISK" | "MEDIUM RISK" | "HIGH RISK" } {
  if (!params.isContract) {
    return { score: 85, riskLevel: "LOW RISK" };
  }

  let score = 100;
  if (!params.sourcifyVerified) score -= 25;
  if (params.isProxy) score -= 15;
  if (params.hasOwnerFn && !params.ownerRenounced) score -= 10;
  for (const sel of params.matchedSelectors) {
    score -= sel.penalty;
  }

  score = Math.max(5, Math.min(100, score));
  const riskLevel = score >= 75 ? "LOW RISK" : score >= 45 ? "MEDIUM RISK" : "HIGH RISK";
  return { score, riskLevel };
}

async function fetchSourcify(chainId: number, address: string): Promise<ScanReport["sourcify"]> {
  try {
    const res = await fetch(`https://sourcify.dev/server/v2/contract/${chainId}/${address}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) {
      return { verified: false, matchType: "unverified", contractName: null, compiler: null };
    }
    const data = (await res.json()) as {
      match?: string;
      compilation?: { name?: string; compilerVersion?: string };
    };
    const matchType =
      data.match === "exact_match" ? "exact_match" : data.match === "match" ? "match" : "unverified";
    return {
      verified: matchType !== "unverified",
      matchType,
      contractName: data.compilation?.name ?? null,
      compiler: data.compilation?.compilerVersion ?? null,
    };
  } catch {
    return { verified: false, matchType: "unverified", contractName: null, compiler: null };
  }
}

export async function scanAddress(chainId: number, rawAddress: string): Promise<ScanReport> {
  const chain = SUPPORTED_CHAINS[chainId];
  if (!chain) {
    throw new Error(`Unsupported chainId: ${chainId}. Supported: 8453 (Base), 4663 (Robinhood Chain).`);
  }
  if (!isAddress(rawAddress)) {
    throw new Error("Invalid EVM address format.");
  }

  const address = rawAddress as `0x${string}`;
  const client = createPublicClient({ transport: http(chain.rpcUrl, { timeout: 8000 }) });

  const [bytecode, balanceWei, txCount, eip1967Slot, sourcify] = await Promise.all([
    client.getCode({ address }),
    client.getBalance({ address }),
    client.getTransactionCount({ address }),
    client.getStorageAt({ address, slot: EIP1967_IMPL_SLOT }).catch(() => "0x" as `0x${string}`),
    fetchSourcify(chainId, address),
  ]);

  const codeHex = bytecode ?? "0x";
  const isContract = codeHex !== "0x" && codeHex.length > 2;
  const inspected = inspectBytecode(codeHex);

  // Check EIP-1967 implementation slot
  let proxyType: "EIP-1967" | "EIP-1167" | null = null;
  let proxyImpl: string | null = null;
  if (eip1967Slot && eip1967Slot.length === 66) {
    const candidate = `0x${eip1967Slot.slice(26)}`.toLowerCase();
    if (candidate !== ZERO_ADDRESS) {
      proxyType = "EIP-1967";
      proxyImpl = candidate;
    }
  }
  if (!proxyType && inspected.isMinimalProxy) {
    proxyType = "EIP-1167";
    proxyImpl = inspected.minimalProxyTarget;
  }

  // Probe ERC-20 & owner() if contract
  let tokenName: string | null = null;
  let tokenSymbol: string | null = null;
  let tokenDecimals: number | null = null;
  let totalSupplyFormatted: string | null = null;
  let ownerAddress: string | null = null;

  if (isContract) {
    const [n, s, d, ts, own] = await Promise.allSettled([
      client.readContract({ address, abi: ERC20_ABI, functionName: "name" }),
      client.readContract({ address, abi: ERC20_ABI, functionName: "symbol" }),
      client.readContract({ address, abi: ERC20_ABI, functionName: "decimals" }),
      client.readContract({ address, abi: ERC20_ABI, functionName: "totalSupply" }),
      client.readContract({ address, abi: ERC20_ABI, functionName: "owner" }),
    ]);

    if (n.status === "fulfilled" && typeof n.value === "string") tokenName = n.value;
    if (s.status === "fulfilled" && typeof s.value === "string") tokenSymbol = s.value;
    if (d.status === "fulfilled" && typeof d.value === "number") tokenDecimals = d.value;
    if (ts.status === "fulfilled" && typeof ts.value === "bigint") {
      totalSupplyFormatted = formatUnits(ts.value, tokenDecimals ?? 18);
    }
    if (own.status === "fulfilled" && typeof own.value === "string") {
      ownerAddress = own.value;
    }
  }

  const hasOwnerFn = Boolean(ownerAddress) || inspected.hasOwnerSelector;
  const ownerRenounced =
    Boolean(ownerAddress) &&
    (ownerAddress!.toLowerCase() === ZERO_ADDRESS || ownerAddress!.toLowerCase() === DEAD_ADDRESS);
  const isErc20 = Boolean(tokenSymbol && totalSupplyFormatted !== null);

  const { score, riskLevel } = computeSafetyScore({
    isContract,
    sourcifyVerified: sourcify.verified,
    isProxy: Boolean(proxyType),
    hasOwnerFn,
    ownerRenounced,
    matchedSelectors: inspected.matchedSelectors,
  });

  const checks: SafetyCheck[] = [];
  if (!isContract) {
    checks.push({
      id: "eoa",
      label: "Externally Owned Account (Wallet)",
      status: "info",
      detail: `Standard EOA wallet with ${txCount} outgoing transactions and ${Number(formatEther(balanceWei)).toFixed(5)} ETH.`,
    });
  } else {
    checks.push({
      id: "sourcify",
      label: "Source Code Verification (Sourcify)",
      status: sourcify.verified ? "pass" : "warn",
      detail: sourcify.verified
        ? `Verified (${sourcify.matchType})${sourcify.contractName ? ` · ${sourcify.contractName}` : ""}`
        : "Source code not found on Sourcify. Inspect bytecode carefully before interacting.",
    });

    checks.push({
      id: "proxy",
      label: "Upgradeable Proxy Check",
      status: proxyType ? "warn" : "pass",
      detail: proxyType
        ? `${proxyType} proxy detected pointing to ${proxyImpl}`
        : "No EIP-1967 or EIP-1167 proxy detected (immutable bytecode).",
    });

    checks.push({
      id: "ownership",
      label: "Admin / Ownership Control",
      status: !hasOwnerFn || ownerRenounced ? "pass" : "warn",
      detail: !hasOwnerFn
        ? "No owner() admin function detected."
        : ownerRenounced
          ? `Ownership renounced (${ownerAddress}).`
          : `Active owner address: ${ownerAddress ?? "detected in bytecode"}`,
    });

    if (inspected.matchedSelectors.length === 0) {
      checks.push({
        id: "selectors",
        label: "High-Risk Admin Selectors",
        status: "pass",
        detail: "No mint, pause, blacklist, mutable fee, or UUPS upgrade selectors detected in bytecode.",
      });
    } else {
      for (const sel of inspected.matchedSelectors) {
        checks.push({
          id: `sel-${sel.selector}`,
          label: `Selector: ${sel.name}`,
          status: sel.severity,
          detail: sel.description,
        });
      }
    }
  }

  return {
    chainId,
    chainName: chain.name,
    address,
    explorerUrl: `${chain.explorerUrl}/address/${address}`,
    scannedAt: new Date().toISOString(),
    isContract,
    bytecodeSizeBytes: inspected.sizeBytes,
    ethBalance: formatEther(balanceWei),
    txCount,
    sourcify,
    proxy: {
      isProxy: Boolean(proxyType),
      type: proxyType,
      implementation: proxyImpl,
    },
    ownership: {
      hasOwnerFn,
      ownerAddress,
      renounced: ownerRenounced,
    },
    token: {
      isErc20,
      name: tokenName,
      symbol: tokenSymbol,
      decimals: tokenDecimals,
      totalSupplyFormatted,
    },
    detectedSelectors: inspected.matchedSelectors.map((s) => s.name),
    score,
    riskLevel,
    checks,
  };
}
