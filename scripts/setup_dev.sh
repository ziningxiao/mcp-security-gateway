#!/bin/bash
# Development setup script

echo "🚀 Setting up MCP Security Gateway development environment..."

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Setup pre-commit hooks
pre-commit install

# Create database
createdb mcp_security_dev

# Run migrations
python scripts/migrate.py

echo "✅ Development environment ready!"
echo "Run 'source venv/bin/activate' to activate the environment"
