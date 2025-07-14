FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY setup.py .
COPY README.md .

# Install the package
RUN pip install -e .

# Copy examples and docs
COPY examples/ ./examples/
COPY docs/ ./docs/

# Change ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import slack_permissions; print('OK')" || exit 1

# Default command
CMD ["python", "-m", "slack_permissions.cli"]

# Multi-stage build for development
FROM base as development

USER root

# Install development dependencies
COPY requirements.txt .
RUN pip install -e ".[dev]"

# Install additional development tools
RUN apt-get update && apt-get install -y \
    git \
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

USER appuser

# Development command
CMD ["python", "-m", "pytest", "--cov=slack_permissions"]

# Multi-stage build for production
FROM base as production

# Remove unnecessary files
RUN rm -rf /app/tests /app/docs /app/examples

# Production command
CMD ["python", "-c", "from slack_permissions import PermissionManager; print('Slack Permission System ready')"]
