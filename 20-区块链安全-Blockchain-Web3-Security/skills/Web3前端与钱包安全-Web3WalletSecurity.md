---
id: 20-004
title: "🖥️ Web3前端与钱包安全 (Web3 Frontend & Wallet Security)"
category: 区块链安全
category_en: "Blockchain/Web3 Security"
difficulty: ★★★★
tools: "MetaMask Security, Ethers.js, Web3.js, WalletConnect, EIP-1193"
last_updated: 2025-07
tags: ["blockchain-security", "web3", "smart-contract", "defi", "solidity"]
subdomain: blockchain-web3-security
nist_csf: ["PR.AC-01", "PR.DS-01"]
mitre_attack: []
---
# 🖥️ Web3前端与钱包安全 (Web3 Frontend & Wallet Security)

## 概述
评估Web3 DApp前端的客户端安全、钱包集成安全、签名逻辑验证和交易模拟，防止前端劫持、钓鱼和签名攻击。

## 核心技能

### 1. DApp前端安全基线

```javascript
// ❌ 不良实践: 直接在前端导入私钥
const privateKey = "0xabc123...";  // ❌ 危险！私钥绝不能在前端

// ✅ 良好实践: 使用EIP-1193标准API
// 通过window.ethereum (MetaMask) 或 WalletConnect连接
import { ethers } from "ethers";

// 安全连接钱包
async function connectWallet() {
    if (!window.ethereum) {
        showError("请安装MetaMask");
        return;
    }
    
    try {
        // 请求账户 - 最小权限
        const accounts = await window.ethereum.request({
            method: "eth_requestAccounts"
        });
        
        // ✅ 验证链ID
        const chainId = await window.ethereum.request({
            method: "eth_chainId"
        });
        
        // 检查是否在正确的链上
        if (chainId !== "0x1") { // Ethereum主网
            await switchToCorrectChain();
        }
        
        // 创建provider
        const provider = new ethers.BrowserProvider(window.ethereum);
        return provider.getSigner();
    } catch (error) {
        console.error("Wallet connection error:", error);
    }
}
```

### 2. 交易安全与模拟

```javascript
// ❌ 不良实践: 不验证交易数据直接签名
async function signAndSendBad(contract, amount) {
    // ❌ 用户不知道自己在签名什么
    const tx = await contract.transfer(to, amount); 
}

// ✅ 良好实践: 模拟交易 + 清晰展示交易内容
async function safeTransfer(contract, to, amount) {
    const signer = provider.getSigner();
    
    // 1. 构建交易
    const txData = await contract.interface.encodeFunctionData("transfer", [to, amount]);
    
    // 2. 模拟交易 (eth_call)
    try {
        await provider.call({
            from: userAddress,
            to: contractAddress,
            data: txData
        });
        console.log("模拟成功");
    } catch (error) {
        showError("交易模拟失败，可能存在问题");
        return;
    }
    
    // 3. 清晰展示交易详情
    showTransactionDetails({
        action: "Transfer",
        token: "USDC",
        from: userAddress,
        to: to,
        amount: ethers.formatUnits(amount, 6),
        gasEstimate: "~150000"
    });
    
    // 4. 用户确认后发送
    const tx = await signer.sendTransaction({
        to: contractAddress,
        data: txData
    });
}

// 使用Blowfish进行交易模拟
import { Blowfish } from "@blowfishxyz/sdk";

const blowfish = new Blowfish({
    apiKey: process.env.BLOWFISH_API_KEY
});

async function simulateTransaction(userAddress, txData) {
    const result = await blowfish.simulateTransaction({
        userAddress,
        transaction: txData,
        metadata: {
            origin: window.location.hostname
        }
    });
    
    // 显示模拟结果
    result.actions.forEach(action => {
        if (action.warning) {
            showWarning(action.message);
        }
    });
}
```

### 3. EIP-712签名安全

```javascript
// EIP-712结构化签名 - 防钓鱼签名
// ❌ 不良实践: 个人签名 (eth_sign / personal_sign) 不易读
const signature = await signer.signMessage("Sign this message"); // ❌ 不安全

// ✅ 良好实践: EIP-712结构化数据签名
const domain = {
    name: "MyDeFiApp",
    version: "1",
    chainId: 1,
    verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
};

const types = {
    Order: [
        { name: "maker", type: "address" },
        { name: "tokenIn", type: "address" },
        { name: "tokenOut", type: "address" },
        { name: "amountIn", type: "uint256" },
        { name: "amountOutMin", type: "uint256" },
        { name: "deadline", type: "uint256" },
        { name: "nonce", type: "uint256" }
    ]
};

const order = {
    maker: userAddress,
    tokenIn: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // USDC
    tokenOut: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH
    amountIn: "1000000", // 1 USDC
    amountOutMin: "500000000000000000", // 0.5 ETH
    deadline: Math.floor(Date.now() / 1000) + 3600,
    nonce: await contract.nonces(userAddress)
};

// 用户可以看到清晰的签名内容
const signature = await signer.signTypedData(domain, types, order);
```

### 4. 常见Web3前端攻击

```text
┌─ Web3前端攻击面 ──────────────────────────────────────────┐
│ 1. 钓鱼dApp                                 │
│    ├─ 假冒的Uniswap/PancakeSwap界面                       │
│    └─ 防护: 验证域名 + ENS + 书签                        │
├──────────────────────────────────────────────────────────┤
│ 2. 水槽(地址替换)攻击                                     │
│    ├─ 恶意JS替换合约地址/收款地址                          │
│    └─ 防护: 硬件钱包显示目标地址 + 地址白名单               │
├──────────────────────────────────────────────────────────┤
│ 3. Approve钓鱼                                            │
│    ├─ 诱导用户无限批准代币使用权限                         │
│    └─ 防护: 使用Permit2 + 有限额度批准                     │
├──────────────────────────────────────────────────────────┤
│ 4. 签名钓鱼                                               │
│    ├─ 使用eth_sign让用户签署不可读信息                      │
│    └─ 防护: MetaMask拒绝eth_sign + EIP-712                 │
├──────────────────────────────────────────────────────────┤
│ 5. RPC劫持                                               │
│    ├─ 恶意RPC节点篡改交易返回                              │
│    └─ 防护: 验证签名结果 + 使用自己的RPC节点                │
├──────────────────────────────────────────────────────────┤
│ 6. 钱包扩展恶意注入                                       │
│    ├─ 恶意Chrome插件篡改交易                              │
│    └─ 防护: 只使用知名钱包, 审查扩展权限                    │
└──────────────────────────────────────────────────────────┘
```

### 5. WalletConnect安全最佳实践

```javascript
// WalletConnect v2安全配置
import WalletConnect from "@walletconnect/client";

const connector = new WalletConnect({
    bridge: "https://bridge.walletconnect.org",
    clientMeta: {
        description: "您的dApp描述",
        url: "https://yourdapp.com",
        icons: ["https://yourdapp.com/icon.png"],
        name: "Your DApp"
    }
});

// ✅ 验证连接的链ID
connector.on("session_update", (error, payload) => {
    const { chainId, accounts } = payload.params[0];
    
    // 验证链ID是否在支持的列表中
    if (!SUPPORTED_CHAIN_IDS.includes(parseInt(chainId))) {
        connector.rejectSession({
            message: "不支持的链"
        });
        return;
    }
    
    // 验证账户数量
    if (accounts.length === 0) {
        disconnect();
    }
});
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| MetaMask | 浏览器钱包 | https://metamask.io/ |
| WalletConnect | 钱包连接协议 | https://walletconnect.com/ |
| Blowfish | 交易模拟 | https://blowfish.xyz/ |
| Revoke Cash | 代币授权检查 | https://revoke.cash/ |
| Ethers.js | Web3库 | https://docs.ethers.org/ |
| Wagmi | React Hooks | https://wagmi.sh/ |

## 参考资源
- [EIP-1193: Ethereum Provider API](https://eips.ethereum.org/EIPS/eip-1193)
- [EIP-712: Typed Data Signing](https://eips.ethereum.org/EIPS/eip-712)
- [WalletConnect Security](https://docs.walletconnect.com/)
- [MetaMask Security Best Practices](https://docs.metamask.io/guide/security.html)
- [OWASP Web3 Security Top 10](https://owasp.org/www-project-web3-security/)
