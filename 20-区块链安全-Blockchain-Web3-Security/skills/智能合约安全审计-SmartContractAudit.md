---
id: 20-001
title: "📝 智能合约安全审计 (Smart Contract Audit)"
category: 区块链安全
category_en: "Blockchain/Web3 Security"
difficulty: ★★★★★
tools: "Slither, Mythril, Certora, Echidna, Foundry, Hardhat"
last_updated: 2025-07
tags: ["blockchain-security", "web3", "smart-contract", "defi", "solidity"]
subdomain: blockchain-web3-security
nist_csf: ["PR.AC-01", "PR.DS-01"]
mitre_attack: []
---
# 📝 智能合约安全审计 (Smart Contract Audit)

## 概述
对Ethereum及其他EVM兼容链上的智能合约进行安全审计，涵盖重入攻击、访问控制、整数溢出、闪电贷攻击等漏洞分析与静态/动态测试。

## 核心技能

### 1. 静态分析工具

```bash
# 使用Slither静态分析
pip install slither-analyzer

# 基础分析
slither contracts/

# 输出详细报告
slither contracts/ --json slither-report.json
slither contracts/ --print human-summary

# 运行特定检测器
slither contracts/ --detect reentrancy-eth
slither contracts/ --detect weak-prng
slither contracts/ --detect naming-convention

# 继承图和调用图
slither contracts/ --print inheritance-graph
slither contracts/ --print call-graph

# 使用Mythril
pip install mythril

# 分析合约
myth analyze contracts/Token.sol

# 指定交易数量
myth analyze contracts/Token.sol --execution-timeout 120

# JSON输出
myth analyze contracts/Token.sol -o json > mythril-report.json

# 使用Aderyn (Rust静态分析器)
cargo install aderyn
aderyn contracts/ -o aderyn-report.md
```

### 2. 常见漏洞模式分析

```solidity
// ❌ 重入攻击 (Reentrancy)
contract VulnerableBank {
    mapping(address => uint) public balances;
    
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        // ❌ 状态更新在外部调用之后
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= _amount;  // ❌ 状态更新太晚
    }
}

// ✅ 修复: Checks-Effects-Interactions模式
contract SecureBank {
    mapping(address => uint) public balances;
    
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        // 1. 先更新状态 (Effects)
        balances[msg.sender] -= _amount;
        // 2. 再执行外部调用 (Interactions)
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
    }
    
    // 或使用ReentrancyGuard
    // import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
}

// ❌ 未检查的返回值和重入
// ✅ 使用 OpenZeppelin 的 ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureBank is ReentrancyGuard {
    mapping(address => uint) public balances;
    
    function withdraw(uint _amount) external nonReentrant {
        require(balances[msg.sender] >= _amount);
        balances[msg.sender] -= _amount;
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success);
    }
}
```

### 3. fuzzing与形式化验证

```solidity
// 使用Foundry进行Fuzzing测试
// 测试文件: test/TokenFuzz.t.sol
import "forge-std/Test.sol";
import "../src/Token.sol";

contract TokenFuzzTest is Test {
    Token token;
    
    function setUp() public {
        token = new Token(1000000 * 1e18);
    }
    
    // Fuzzing测试: 随机输入
    function testFuzz_Transfer(address from, address to, uint amount) public {
        vm.assume(from != address(0) && to != address(0));
        vm.assume(from != to);
        vm.assume(amount <= token.balanceOf(from));
        
        vm.prank(from);
        token.transfer(to, amount);
        
        assertEq(token.balanceOf(to), amount);
    }
}

// 使用Echidna进行属性测试
// 属性文件: test/invariant/TokenInvariants.sol
contract TokenInvariants {
    Token token;
    
    constructor() {
        token = new Token(1000000 * 1e18);
    }
    
    // 不变量: 总供应量不应改变
    function test_total_supply_invariant() public {
        assert(token.totalSupply() == token.balanceOf(address(0x1)) + 
               token.balanceOf(address(0x2)));
    }
    
    // 使用Echidna运行
    // echidna test/invariant/TokenInvariants.sol --contract TokenInvariants
}

// 使用Certora Prover (形式化验证)
// certoraRun spec/Token.spec contracts/Token.sol
```

### 4. DeFi常见攻击向量

| 漏洞类型 | 严重程度 | 知名案例 | 检测工具 |
|:---|:---:|:---|:---:|
| 重入攻击 | 🔴 严重 | The DAO $60M | Slither reentrancy |
| 闪电贷攻击 | 🔴 严重 | bZx, Harvest, Pancake | 手动审查+Fuzzing |
| 价格操控 | 🔴 严重 | TWAP操控 | Echidna+Fuzz |
| 精度损失 | 🟠 高危 | 向下取整问题 | Slither |
| 未检查的外部调用 | 🟠 高危 | Multi-sign漏洞 | Slither low-level-calls |
| 访问控制缺陷 | 🔴 严重 | Parity钱包漏洞 | Slither access-control |
| 签名重放 | 🟠 高危 | Permits跨链重放 | 手动审查 |
| 委任调用 | 🔴 严重 | Parity库合约 | Slither controlled-delegatecall |
| 前端抢跑 | 🟠 高危 | Sandwich攻击 | 手动审查 |
| 治理攻击 | 🟠 高危 | 闪电贷投票 | 手动审查 |

### 5. SWC缺陷分类

```bash
# SWC (Smart Contract Weakness Classification) 关键条目
# SWC-100: Function Default Visibility (函数默认可见性)
# SWC-101: Integer Overflow and Underflow
# SWC-102: Outdated Compiler Version
# SWC-103: Floating Pragma
# SWC-104: Unchecked Call Return Value
# SWC-105: Unprotected Ether Withdrawal
# SWC-106: Unprotected SELFDESTRUCT Instruction
# SWC-107: Reentrancy
# SWC-108: State Variable Default Visibility
# SWC-109: Uninitialized Storage Pointer
# SWC-110: Assert Violation
# SWC-111: Use of Deprecated Solidity Functions
# SWC-112: Delegatecall to Untrusted Callee
# SWC-113: DoS with Failed Call
# SWC-114: Transaction Order Dependence
# SWC-115: Authorization through tx.origin
# SWC-116: Timestamp Dependence
# SWC-117: Insufficient Gas Griefing
# SWC-118: Incorrect Constructor Name
# SWC-119: Shadowing State Variables
# SWC-120: Weak Sources of Randomness
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Slither | 静态分析框架 | https://github.com/crytic/slither |
| Mythril | 符号执行分析 | https://github.com/Consensys/mythril |
| Foundry | 开发测试框架 | https://github.com/foundry-rs/foundry |
| Echidna | Fuzzing测试 | https://github.com/crytic/echidna |
| Certora Prover | 形式化验证 | https://www.certora.com/ |
| Aderyn | Rust静态分析器 | https://github.com/Cyfrin/aderyn |

## 参考资源
- [SWC Registry](https://swcregistry.io/)
- [OpenZeppelin Security Best Practices](https://docs.openzeppelin.com/contracts/5.x/security-considerations)
- [Ethereum Smart Contract Security](https://ethereum.org/en/developers/docs/smart-contracts/security/)
- [DASP Top 10](https://dasp.co/)
- [Consensys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
