FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MCP_TRANSPORT=http \
    MCP_BIND_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    MCP_PATH=/mcp

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ufw_mcp/ ./ufw_mcp/

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /audit /keys && chown appuser:appuser /audit /keys
USER appuser

EXPOSE 8000
CMD ["python", "-m", "ufw_mcp.server"]
