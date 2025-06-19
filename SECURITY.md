# Security Policy

## Supported Versions

We take security seriously at Privatus-chat. The following versions are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

### DO NOT Create Public Issues

If you discover a security vulnerability, please **DO NOT** create a public GitHub issue. Instead, please report it responsibly using one of the following methods:

### 1. Email (Preferred)

Send details to: **security@privatus-chat.org**

Please encrypt your email using our PGP key:
```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP Key would be here in production]
-----END PGP PUBLIC KEY BLOCK-----
```

### 2. GitHub Security Advisory

Use GitHub's private security advisory feature:
1. Go to the Security tab
2. Click "Report a vulnerability"
3. Fill out the form with details

### What to Include

When reporting a vulnerability, please include:

- **Description**: Clear explanation of the vulnerability
- **Impact**: What can an attacker achieve?
- **Steps to Reproduce**: Detailed steps to trigger the vulnerability
- **Affected Versions**: Which versions are vulnerable?
- **Proof of Concept**: Code or screenshots if applicable
- **Suggested Fix**: If you have ideas for remediation

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity (see below)

### Severity Levels

| Severity | Description | Fix Timeline |
|----------|-------------|--------------|
| Critical | Remote code execution, key compromise | 24-48 hours |
| High | Data breach, authentication bypass | 7 days |
| Medium | Information disclosure, DoS | 30 days |
| Low | Minor issues with limited impact | 90 days |

## Security Measures

### What We Do

- **Code Review**: All code is reviewed before merge
- **Automated Security Scanning**: Regular vulnerability scans
- **Dependency Updates**: Regular updates of dependencies
- **Security Audits**: Periodic third-party audits
- **Bug Bounty Program**: Rewards for responsible disclosure

### Cryptographic Implementations

Our cryptographic implementations use:
- **Algorithms**: Only NIST-approved or widely-audited algorithms
- **Libraries**: Well-maintained, audited cryptographic libraries
- **Key Management**: Secure key generation and storage
- **Random Numbers**: Cryptographically secure random number generators

### Secure Development

- **Principle of Least Privilege**: Minimal permissions required
- **Defense in Depth**: Multiple layers of security
- **Input Validation**: All user input is validated
- **Output Encoding**: Proper encoding to prevent injection
- **Error Handling**: Secure error messages without information leakage

## Bug Bounty Program

We run a bug bounty program to reward security researchers.

### Scope

In scope:
- Privatus-chat application (all versions)
- Cryptographic implementations
- Network protocols
- Key management systems
- Authentication mechanisms

Out of scope:
- Denial of Service attacks
- Social engineering
- Physical attacks
- Attacks requiring physical access

### Rewards

Rewards are based on severity and impact:

| Severity | Reward Range |
|----------|--------------|
| Critical | $1,000 - $5,000 |
| High | $500 - $1,000 |
| Medium | $100 - $500 |
| Low | $50 - $100 |

### Rules

1. **Responsible Disclosure**: Report privately first
2. **No Damage**: Don't harm users or systems
3. **No Data Theft**: Don't access user data
4. **Good Faith**: Act in good faith
5. **No Public Disclosure**: Wait for fix before public disclosure

## Security Features

### End-to-End Encryption
- Signal Protocol implementation
- Perfect forward secrecy
- Post-compromise security

### Anonymous Routing
- Onion routing for metadata protection
- Traffic analysis resistance
- No IP address leakage

### Secure Storage
- Encrypted local database
- Secure key storage
- Automatic secure deletion

### Network Security
- Certificate pinning
- Man-in-the-middle protection
- Secure peer verification

## Disclosure Policy

### Coordinated Disclosure

1. **Report Received**: We acknowledge receipt
2. **Verification**: We verify the vulnerability
3. **Fix Development**: We develop a fix
4. **Testing**: Thorough testing of the fix
5. **Release**: Security update released
6. **Disclosure**: Coordinated public disclosure

### Credit

We credit researchers who:
- Report valid vulnerabilities
- Follow responsible disclosure
- Work with us on fixes

Credits appear in:
- Security advisories
- Release notes
- Hall of Fame

## Security Advisories

Past security advisories can be found in the [Security Advisories](https://github.com/privatus-chat/privatus-chat/security/advisories) section.

## Contact

- **Email**: security@privatus-chat.org
- **PGP Key**: [Download](https://privatus-chat.org/pgp-key.asc)
- **Bug Bounty**: bounty@privatus-chat.org

## Commitment

We are committed to:
- Fast response to security issues
- Transparent communication
- Regular security updates
- Continuous security improvement

---

*Thank you for helping keep Privatus-chat secure!* 