# Deploying

Configuration is entirely environment-driven. Copy `.env.example` to `.env`,
fill in your own values, and run the server.

    cp .env.example .env
    docker compose up -d

Behind a reverse proxy, terminate TLS at the proxy and forward to the container
port set in `.env`. If the server uses Microsoft Entra ID, register an
application in your own tenant; the App ID URI, identifier URI and MCP base URL
must agree.

Every hostname, address and identifier in this repository is a placeholder.
