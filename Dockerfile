# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml ./
COPY src/ ./src/

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Copy configuration file
COPY config.yaml.example ./config.yaml.example

# Expose MCP server port (if using stdio, this is not strictly necessary)
# MCP typically uses stdio, but exposing for future network-based communication
EXPOSE 3000

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Health check (optional)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default command - run the MCP server
CMD ["python", "-m", "sentinel_mcp.server", "--config", "config.yaml"]
