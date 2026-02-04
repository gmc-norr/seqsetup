"""Swagger UI routes for API documentation."""

import json

from fasthtml.common import *
from starlette.responses import JSONResponse, Response

from ..openapi import get_openapi_spec


def register(app, rt):
    """Register Swagger UI routes."""

    @app.get("/api/docs")
    def swagger_ui(req):
        """Serve Swagger UI."""
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SeqSetup API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin: 0; background: #fafafa; }
        .swagger-ui .topbar { display: none; }
        .swagger-ui .info .title { font-size: 2rem; }
        .swagger-ui .info { margin: 30px 0; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: "/api/openapi.json",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                persistAuthorization: true,
                tryItOutEnabled: true,
            });
            window.ui = ui;
        };
    </script>
</body>
</html>"""
        return Response(content=html_content, media_type="text/html")

    @app.get("/api/openapi.json")
    def openapi_spec(req):
        """Serve OpenAPI specification as JSON."""
        return JSONResponse(get_openapi_spec())

    @app.get("/api/openapi.yaml")
    def openapi_spec_yaml(req):
        """Serve OpenAPI specification as YAML."""
        import yaml
        spec = get_openapi_spec()
        yaml_content = yaml.dump(spec, default_flow_style=False, sort_keys=False, allow_unicode=True)
        return Response(content=yaml_content, media_type="text/yaml")
