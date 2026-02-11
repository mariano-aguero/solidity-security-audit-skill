# Contributing

Thanks for your interest in contributing to the Solidity Security Audit Skill!

## How to Contribute

### Reporting Issues

- Check if the issue already exists
- Use a clear and descriptive title
- Provide as much context as possible

### Suggesting Enhancements

- Open an issue describing the enhancement
- Explain why this would be useful
- Include examples if applicable

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Commit with clear messages (`git commit -m 'Add amazing feature'`)
5. Push to your branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## Content Guidelines

When updating skill documentation:

| Content Type | File | Guidelines |
|--------------|------|------------|
| Vulnerability patterns | `references/vulnerability-taxonomy.md` | Include SWC ID, vulnerable + secure code examples |
| DeFi checklists | `references/defi-checklist.md` | Use checkbox format, organize by protocol type |
| Tool updates | `references/tool-integration.md` | Add commands, detectors, configuration |
| Detection patterns | `references/automated-detection.md` | Include regex, severity, recommendation |
| L2/Cross-chain | `references/l2-crosschain.md` | New networks, bridge patterns, sequencer info |
| Account Abstraction | `references/account-abstraction.md` | ERC-4337 patterns, Entry Point versions |

## Severity Classification

Follow Immunefi/Sherlock/Code4rena standards:

- **Critical**: Direct loss of funds, permanent protocol corruption
- **High**: Conditional loss of funds, significant disruption
- **Medium**: Indirect loss, limited impact with specific conditions
- **Low**: Best practice violations, theoretical edge cases
- **Informational**: Code quality, gas optimizations

## Questions?

Feel free to open an issue for any questions about contributing.
