# Contributing to Qurox Post-Quantum Cryptography Library

Thank you for your interest in contributing to the Qurox PQ library! This document outlines the process for contributing and the legal requirements.

## Before You Start

### Legal Requirements

By contributing to this project, you agree that:

1. **License Agreement**: Your contributions will be licensed under the Apache License 2.0
2. **Copyright**: Philippe Lecrosnier retains copyright ownership of the overall project
3. **Attribution**: Your contributions will be acknowledged in the AUTHORS file
4. **Rights**: You have the legal right to make your contributions under these terms

### Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Maintain professional communication
- Follow security best practices

## How to Contribute

### 1. Setting Up Your Environment

```bash
# Clone the repository
git clone https://github.com/zxfae/Qurox-pq.git
cd qurox-pq

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build the project
cargo build

# Run tests
cargo test
```

### 2. Making Changes

1. **Fork** the repository on GitHub
2. **Create a branch** for your feature: `git checkout -b feature/your-feature-name`
3. **Make your changes** following our coding standards
4. **Add tests** for new functionality
5. **Ensure all tests pass**: `cargo test`
6. **Run formatting**: `cargo fmt`
7. **Run linting**: `cargo clippy`

### 3. Coding Standards

#### File Headers
All `.rs` files must include the Apache 2.0 copyright header:

```rust
// Copyright 2025 Philippe Lecrosnier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Module documentation here
```

Use the provided `add-headers.sh` script to automatically add headers.

#### Code Style
- Follow Rust standard formatting (`cargo fmt`)
- Use meaningful variable and function names
- Add comprehensive documentation for public APIs
- Include examples in documentation where appropriate
- Follow the existing code architecture patterns

#### Security Requirements
- All cryptographic implementations must follow established standards
- Use constant-time operations where applicable
- Properly handle sensitive data (use zeroization)
- Include comprehensive tests for security-critical code

### 4. Testing

- **Unit tests**: Test individual functions and modules
- **Integration tests**: Test complete workflows
- **Security tests**: Test against known attack vectors
- **Performance tests**: Benchmark critical operations

```bash
# Run all tests
cargo test

# Run tests with all features
cargo test --all-features

# Run specific test
cargo test test_name
```

### 5. Documentation

- Update README.md if adding new features
- Add inline documentation for public APIs
- Include examples for complex functionality
- Update CHANGELOG.md for significant changes

## Pull Request Process

### 1. Before Submitting

- [ ] All tests pass locally
- [ ] Code is properly formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] Documentation is updated
- [ ] Copyright headers are present in new files
- [ ] CHANGELOG.md is updated (if applicable)

### 2. Pull Request Template

When submitting a PR, include:

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Security improvement

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Added new tests for this change

## Legal Compliance
- [ ] I agree to license my contributions under Apache License 2.0
- [ ] I acknowledge Philippe Lecrosnier's copyright ownership
- [ ] I have the legal right to make these contributions
- [ ] I have added appropriate copyright headers to new files

## Additional Notes
Any additional information or context
```

### 3. Review Process

1. **Automated checks**: GitHub Actions will run tests and linting
2. **Security review**: Cryptographic changes require thorough security review
3. **Code review**: Maintainers will review for code quality and design
4. **Legal review**: Ensure license compliance
5. **Merge**: Once approved, changes will be merged

## Security Contributions

For security-related contributions:

1. **Responsible disclosure**: Report security issues privately first
2. **Testing**: Include comprehensive security tests
3. **Documentation**: Document security assumptions and guarantees
4. **Review**: Security changes require additional review time

Contact: lecro.philippe@icloud.com for security-related discussions.

## Questions and Support

- **GitHub Issues**: For bug reports and feature requests
- **Discussions**: For general questions and community discussion
- **Email**: lecro.philippe@icloud.com for direct communication

## License Summary

This project is licensed under the Apache License 2.0. Key points:

- **Commercial use allowed**
- **Modification allowed**
- **Distribution allowed**
- **Must include license and copyright notice**
- **Must state changes made to the code**
- **No trademark use without permission**
- **No warranty provided**

Full license text available in the [LICENSE](LICENSE) file.

---

Thank you for contributing to making post-quantum cryptography accessible and secure!