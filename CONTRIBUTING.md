# Contributing to AmpliFilter

First off, thank you for taking the time to contribute! AmpliFilter is built by the community for network defenders, penetration testers and security researchers. 

Please take a moment to review the guidelines below to ensure a smooth contribution process.

## Code of Conduct
By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please report unacceptable behaviour to the repository maintainers.

## How Can I Contribute?

### 1. Reporting Bugs & Issues
If you encounter a bug, incorrect payload calculation, or unexpected socket exception:
- Use the **Issue Tracker** to open a bug report.
- Provide clear reproduction steps, Python version, OS details and relevant log outputs (with sensitive network ranges redacted).

### 2. Suggesting New Protocols & Payloads
AmpliFilter relies on precise UDP probe payloads to identify amplification reflectors. If you want to propose a new protocol addition, or potentially a different or optimised payload option for an existing protocol:
- Provide RFC documentation or technical references supporting the payload structure.
- Explain why this payload is suitable for its intended purpose (e.g. creates more amplified traffic).

### 3. Code Contributions & Pull Requests
We welcome code contributions, especially as we transition toward our **v2.0 asynchronous (`asyncio`) release**.

#### Development Workflow:
1. **Fork** the repository and create your feature branch from `main`:
   ```shell
   git switch -c feature/async-socket-engine
   ```
2. Write clean, Pythonic code.
   - Adhere to Python 3.12+ standards.
   - Keep logs clean.
3. Test your changes thoroughly.
4. Submit a Pull Request and provide a concise description of what your PR solves or implements.