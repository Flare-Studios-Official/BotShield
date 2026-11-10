# Contributing to BotShield

Thank you for your interest in contributing to **BotShield**! We welcome bug reports, feature suggestions, detection heuristic improvements, and code contributions.

## Development Workflow

1. Fork the repository and create a feature branch (`git checkout -b feature/new-signal`).
2. Set up the Python virtual environment and install test dependencies:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```
3. Set up frontend dependencies:
   ```bash
   cd frontend
   npm install
   ```
4. Run the automated test suite before opening a pull request:
   ```bash
   cd backend
   python -m pytest tests -v
   cd ../frontend
   npm run build
   ```
5. Ensure all commits adhere to clear, descriptive commit messages.
6. Submit a Pull Request targeting the `main` branch.

## Coding Standards

- **Python**: Follow PEP 8 guidelines and include explicit type annotations.
- **SSRF Safety**: Any new outbound network requests MUST pass through `app.core.security.validate_and_resolve_url`.
- **Zero Fabrication**: New features must never return simulated data in production mode.
- **Frontend**: Clean TypeScript components styled with Tailwind CSS, supporting accessible contrast and dark mode aesthetics.
