# Implementation Roadmap and Technical Clarifications

**Version:** 2.0.6
**Date:** July 27, 2025  
**Purpose:** Clarify technical requirements and provide actionable implementation plan  

## 1. Technical Clarifications

### 1.1 Addressing Documentation Inconsistencies

I noticed some inconsistencies in the provided documents that need clarification:

**Issue 1: Terminology Consistency**
- Technical specs v2.0.3 mentioned "P2WSH-via-P2SH" in some places
- KIP document consistently uses "P2PKH-Blake2b-256-via-P2SH"
- **Confirmed**: Use P2PKH-Blake2b-256-via-P2SH as specified in KIP

**Issue 2: Script Structure Clarification**  
- **Confirmed**: Script for address: `<PUB_KEY> OP_CHECKSIG`
- **Spending scriptSig**: `<SIGNATURE> <PUB_KEY> OP_CHECKSIG`
- Address generation: `Bech32(Blake2b(<PUB_KEY> OP_CHECKSIG))`
- **Standard P2SH pattern** with script revelation during spending

**Issue 3: CLI Tool Naming**
- Original specs created `kaspa-p2pkh-blake2b` CLI
- v2.0.3 wants to enhance existing `kaspa-cli`
- **Resolution**: Enhance existing kaspa-cli with `--p2pkh-blake2b256` flag

### 1.2 Confirmed Technical Approach

```rust
// CONFIRMED: Standard P2SH with Simple Script
pub fn create_p2pkh_blake2b256_address(pubkey: &[u8; 32]) -> Address {
    // Script: <PUB_KEY> OP_CHECKSIG
    let mut script = Vec::with_capacity(33);
    script.extend_from_slice(pubkey);  // 32 byte pubkey
    script.push(0xac);                 // OP_CHECKSIG
    
    // Hash the script for P2SH
    let script_hash = blake2b_256(&script);
    
    // Bech32 encode script hash
    Address::new_script_hash(script_hash, network)
}

// Spending: scriptSig = <SIGNATURE> <SCRIPT>
pub fn create_script_sig(signature: &[u8; 64], script: &[u8]) -> Vec<u8> {
    let mut script_sig = Vec::with_capacity(97);
    script_sig.extend_from_slice(signature);  // 64 bytes
    script_sig.extend_from_slice(script);     // 33 bytes: <PUB_KEY> OP_CHECKSIG
    script_sig  // Total: 97 bytes
}
```

## 2. Detailed Implementation Plan

### 2.1 Week 1: Core Library Enhancement

**Day 1-2: Project Setup**
```bash
# Enhance existing kaspa-addresses crate
cd rusty-kaspa/crypto/addresses
git checkout -b feature/p2pkh-blake2b256-addresses

# Add P2PKH-Blake2b-256 module
touch src/p2pkh_blake2b256.rs
```

**Day 3-4: Core Implementation**
```rust
// File: src/p2pkh_blake2b256.rs
use crate::{Address, NetworkType, AddressError};
use kaspa_hashes::blake2b_256;

#[derive(Debug, Clone, PartialEq)]
pub struct P2PKHBlake2b256Address {
    inner: Address,
}

impl P2PKHBlake2b256Address {
    pub fn from_public_key(
        pubkey: &[u8; 32], 
        network: NetworkType
    ) -> Result<Self, AddressError> {
        // Script: <PUB_KEY> OP_CHECKSIG
        let mut script = Vec::with_capacity(33);
        script.extend_from_slice(pubkey);  // 32 bytes
        script.push(0xac);                 // OP_CHECKSIG
        
        let script_hash = blake2b_256(&script);
        let address = Address::new_script_hash(script_hash, network)?;
        Ok(Self { inner: address })
    }
    
    pub fn create_script_sig(&self, signature: &[u8; 64], pubkey: &[u8; 32]) -> Vec<u8> {
        // scriptSig: <SIGNATURE> <PUB_KEY> OP_CHECKSIG
        let mut script_sig = Vec::with_capacity(97);
        script_sig.extend_from_slice(signature);  // 64 bytes
        script_sig.extend_from_slice(pubkey);     // 32 bytes  
        script_sig.push(0xac);                    // OP_CHECKSIG
        script_sig
    }
    
    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }
    
    pub fn analyze_security(&self) -> SecurityLevel {
        SecurityLevel::ShorResistant
    }
}

#[derive(Debug, PartialEq)]
pub enum SecurityLevel {
    ECDLPVulnerable,  // P2PK addresses vulnerable to Shor's algorithm
    ShorResistant,    // P2PKH-Blake2b-256 addresses
    Unknown,
}
```

**Day 5: Testing Framework**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_address_generation() {
        let pubkey = [0x02; 32]; // Test public key
        let address = P2PKHBlake2b256Address::from_public_key(
            &pubkey, 
            NetworkType::Testnet
        ).unwrap();
        
        let addr_str = address.to_string();
        assert!(addr_str.starts_with("kaspatest:"));
        assert_eq!(addr_str.len(), 63); // Standard Kaspa address length
    }
    
    #[test]
    fn test_public_key_hiding() {
        let pubkey = [0x42; 32];
        let address = P2PKHBlake2b256Address::from_public_key(
            &pubkey, 
            NetworkType::Testnet
        ).unwrap();
        
        // Verify public key doesn't appear in address
        let addr_bytes = address.inner.payload();
        assert!(!addr_bytes.windows(32).any(|w| w == pubkey));
    }
    
    #[test]
    fn test_deterministic_generation() {
        let pubkey = [0x99; 32];
        let addr1 = P2PKHBlake2b256Address::from_public_key(&pubkey, NetworkType::Mainnet).unwrap();
        let addr2 = P2PKHBlake2b256Address::from_public_key(&pubkey, NetworkType::Mainnet).unwrap();
        assert_eq!(addr1.to_string(), addr2.to_string());
    }
}
```

### 2.2 Day 6-8: CLI Enhancement

**Enhance existing kaspa-cli**
```rust
// File: cli/src/modules/address.rs (enhanced)
use kaspa_addresses::p2pkh_blake2b256::P2PKHBlake2b256Address;

#[derive(Args)]
pub struct AddressCommand {
    /// Public key (hex encoded)
    pub public_key: String,
    
    /// Network type
    #[arg(short, long, default_value = "testnet")]
    pub network: NetworkType,
    
    /// Generate P2PKH-Blake2b-256 address (Shor's algorithm resistant)
    #[arg(long)]
    pub p2pkh_blake2b256: bool,
    
    /// Skip security warnings (not recommended)
    #[arg(long)]
    pub skip_warnings: bool,
}

pub fn handle_address_command(args: AddressCommand) -> Result<(), CliError> {
    let pubkey = parse_hex_pubkey(&args.public_key)?;
    
    if args.p2pkh_blake2b256 {
        generate_p2pkh_blake2b256_address(&pubkey, args.network)
    } else {
        if !args.skip_warnings {
            display_security_warning();
        }
        generate_legacy_address(&pubkey, args.network)
    }
}

fn generate_p2pkh_blake2b256_address(
    pubkey: &[u8; 32], 
    network: NetworkType
) -> Result<(), CliError> {
    let address = P2PKHBlake2b256Address::from_public_key(pubkey, network)?;
    
    println!("🛡️  P2PKH-BLAKE2B-256 ADDRESS GENERATED");
    println!();
    println!("Address: {}", address.to_string());
    println!("Type: Script Hash (P2SH)");
    println!("Script: <PUB_KEY> OP_CHECKSIG");
    println!("Spending: <SIGNATURE> <PUB_KEY> OP_CHECKSIG");
    println!("Security: Protected against Shor's algorithm ECDLP attacks");
    println!();
    println!("[+] Security Benefits:");
    println!("  • Public key hidden until spending");
    println!("  • Resistant to ECDLP attacks via Shor's algorithm");
    println!("  • Uses Blake2b-256 hash commitment");
    println!("  • Backward compatible with existing nodes");
    println!();
    println!("[#] Technical Details:");
    println!("  • Input Size: ~134 bytes (vs ~96 bytes legacy)");
    println!("  • Protection: Immediate");
    println!("  • Consensus: No changes required");
    
    Ok(())
}

fn display_security_warning() {
    println!("[!]  SECURITY WARNING");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("You are generating a LEGACY address that is");
    println!("VULNERABLE to ECDLP attacks via Shor's algorithm!");
    println!();
    println!("[!] RISKS:");
    println!("  • Public key exposed immediately");
    println!("  • Shor's algorithm can solve ECDLP to extract private key");
    println!("  • No protection against cryptographically relevant quantum computers");
    println!();
    println!("🛡️  STRONGLY RECOMMENDED:");
    println!("  Use --p2pkh-blake2b256 flag for Shor's algorithm protection");
    println!();
    println!("Continue with vulnerable address? (y/N): ");
    
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    if input.trim().to_lowercase() != "y" {
        println!("Aborted. Use --p2pkh-blake2b256 for security.");
        std::process::exit(1);
    }
}
```

### 2.3 Day 8-10: Transaction Support

**Script Validation Enhancement**
```rust
// File: crypto/txscript/src/lib.rs (enhanced)
pub fn validate_p2pkh_blake2b256_script(
    script_sig: &[u8],
    script_pubkey: &[u8],
    tx: &Transaction,
    input_index: usize,
) -> Result<bool, ScriptError> {
    // Parse scriptSig: <signature> <pubkey> <redeemScript>
    let mut offset = 0;
    
    // Extract signature
    let sig_len = script_sig[offset] as usize;
    offset += 1;
    let signature = &script_sig[offset..offset + sig_len];
    offset += sig_len;
    
    // Extract public key
    let pubkey_len = script_sig[offset] as usize;
    offset += 1;
    let pubkey = &script_sig[offset..offset + pubkey_len];
    offset += pubkey_len;
    
    // Extract redeem script
    let script_len = script_sig[offset] as usize;
    offset += 1;
    let redeem_script = &script_sig[offset..offset + script_len];
    
    // Verify script hash matches
    let computed_hash = blake2b_256(redeem_script);
    let expected_hash = &script_pubkey[2..34]; // Skip version bytes
    if computed_hash != expected_hash {
        return Ok(false);
    }
    
    // Execute redeem script
    let mut stack = vec![signature.to_vec(), pubkey.to_vec()];
    execute_p2pkh_blake2b256_script(redeem_script, &mut stack)?;
    
    // Verify signature
    if stack.len() != 1 || stack[0] != vec![1] {
        return Ok(false);
    }
    
    verify_transaction_signature(signature, pubkey, tx, input_index)
}

fn execute_p2pkh_blake2b256_script(
    script: &[u8], 
    stack: &mut Vec<Vec<u8>>
) -> Result<(), ScriptError> {
    let mut pc = 0;
    
    while pc < script.len() {
        match script[pc] {
            0x76 => { // OP_DUP
                let top = stack.last().unwrap().clone();
                stack.push(top);
            }
            0xb2 => { // OP_BLAKE2B256
                let input = stack.pop().unwrap();
                let hash = blake2b_256(&input);
                stack.push(hash.to_vec());
            }
            0x20 => { // Push 32 bytes
                pc += 1;
                let data = script[pc..pc + 32].to_vec();
                stack.push(data);
                pc += 31; // Will be incremented by loop
            }
            0x88 => { // OP_EQUALVERIFY
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a != b {
                    return Err(ScriptError::EqualVerifyFailed);
                }
            }
            0xac => { // OP_CHECKSIG
                // This will be handled by verify_transaction_signature
                stack.push(vec![1]); // Placeholder for success
            }
            _ => return Err(ScriptError::UnknownOpcode),
        }
        pc += 1;
    }
    
    Ok(())
}
```

### 2.4 Day 10-13: Integration and Testing

**Comprehensive Test Suite**
```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[test]
    fn test_end_to_end_transaction() {
        // Generate P2PKH-Blake2b-256 address
        let keypair = generate_test_keypair();
        let address = P2PKHBlake2b256Address::from_public_key(
            &keypair.public_key(), 
            NetworkType::Testnet
        ).unwrap();
        
        // Create funding transaction
        let funding_tx = create_p2sh_funding_transaction(&address, 1_000_000);
        
        // Create spending transaction
        let spending_tx = create_p2pkh_blake2b256_spending_transaction(
            &keypair,
            &funding_tx,
            0, // output index
            500_000, // amount to spend
        );
        
        // Validate spending transaction
        assert!(validate_transaction(&spending_tx).is_ok());
    }
    
    #[test]
    fn test_cli_integration() {
        let pubkey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        
        // Test P2PKH-Blake2b-256 generation
        let args = AddressCommand {
            public_key: pubkey.to_string(),
            network: NetworkType::Testnet,
            p2pkh_blake2b256: true,
            skip_warnings: false,
        };
        
        assert!(handle_address_command(args).is_ok());
    }
}
```

**Performance Benchmarks**
```rust
#[cfg(test)]
mod benchmarks {
    use criterion::{black_box, criterion_group, criterion_main, Criterion};
    
    fn benchmark_address_generation(c: &mut Criterion) {
        let pubkey = [0x42; 32];
        
        c.bench_function("legacy_address", |b| {
            b.iter(|| {
                Address::new_pubkey(black_box(&pubkey), NetworkType::Testnet)
            })
        });
        
        c.bench_function("p2pkh_blake2b256_address", |b| {
            b.iter(|| {
                P2PKHBlake2b256Address::from_public_key(
                    black_box(&pubkey), 
                    NetworkType::Testnet
                )
            })
        });
    }
    
    criterion_group!(benches, benchmark_address_generation);
}
```

## 3. Validation Checklist

### 3.1 Technical Requirements 

- [ ] **Zero Breaking Changes**: All existing functionality works unchanged
- [ ] **Optional Enhancement**: Shor's algorithm resistance available via `--p2pkh-blake2b256` flag
- [ ] **Existing Infrastructure**: Uses kaspa-hashes Blake2b and kaspa-addresses P2SH
- [ ] **Security Analysis**: Addresses can be analyzed for Shor's algorithm resistance
- [ ] **Performance**: Address generation <1ms, acceptable transaction overhead

### 3.2 Security Requirements 

- [ ] **Public Key Hiding**: PK hidden until spending transaction
- [ ] **Shor's Algorithm Resistance**: Protected against Shor's algorithm on ECDLP
- [ ] **Hash Security**: Uses Blake2b-256 for collision resistance
- [ ] **Script Validation**: Proper P2SH validation with redeem scripts
- [ ] **Legacy Detection**: Can identify and warn about ECDLP-vulnerable addresses

### 3.3 User Experience Requirements 

- [ ] **Default Security**: CLI warns about legacy address risks
- [ ] **Educational Output**: Clear security benefit explanations
- [ ] **Migration Path**: Clear guidance for upgrading from legacy
- [ ] **Compatibility**: Works with existing Kaspa infrastructure

## 4. Production Deployment Strategy

### 4.1 Testing Phase (Day 12-13)
```bash
# Comprehensive testing
cargo test --all-features
cargo bench
cargo clippy -- -D warnings
cargo audit

# Integration testing
./scripts/test_p2pkh_blake2b256_integration.sh
```

### 4.2 Documentation Phase (Day X)
- API documentation with rustdoc
- Security analysis whitepaper
- Developer migration guide
- User education materials

### 4.3 Community Review (Day Y)
- Submit PR to rusty-kaspa repository
- KIP proposal submission
- Community feedback integration
- Security audit coordination

## 5. Success Metrics

### 5.1 Adoption and Public Awareness (Ongoing?)
- [ ]  CLI integration without breaking changes
- [ ]  Clear security warnings for legacy usage
- [ ]  Educational output explaining Shor's algorithm protection benefits
- [ ]  Community acceptance and positive feedback

