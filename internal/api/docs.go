package api

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openAPISpec []byte

const docsHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Cerberus API</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui.css"/>
  <meta name="color-scheme" content="light only"/>
  <style>
    html { color-scheme: light only; }
    body { margin: 0; background: #f7f9fb; color: #121820; }
    .topbar { display: none; }
    .swagger-ui .scheme-container { background: #fff; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({
      url: "/openapi.yaml",
      dom_id: "#swagger-ui",
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis],
      layout: "BaseLayout"
    });
  </script>
</body>
</html>
`

// docsContentSecurityPolicy allows Swagger UI assets from unpkg for /docs only.
const docsContentSecurityPolicy = "default-src 'none'; " +
	"script-src https://unpkg.com 'unsafe-inline'; " +
	"style-src https://unpkg.com 'unsafe-inline'; " +
	"img-src 'self' data: https://unpkg.com; " +
	"font-src 'self' data: https://unpkg.com; " +
	"connect-src 'self'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

func (s *Server) registerDocsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /openapi.yaml", s.handleOpenAPI)
	mux.HandleFunc("GET /docs", s.handleDocsUI)
	mux.HandleFunc("GET /docs/", s.handleDocsUI)
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write(openAPISpec)
}

func (s *Server) handleDocsUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(docsHTML))
}
