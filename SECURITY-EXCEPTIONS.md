# Security exceptions

Scanner findings that are accepted rather than fixed. Each entry has an
owner and a review date no more than 90 days out.

| ID | Where | Why it is acceptable | Owner | Review by |
|----|-------|----------------------|-------|-----------|
| gitleaks `slack-webhook-url` | `configs/alerts.notifications.yaml:24` (since 44cc54e) | Documentation placeholder with all-zero team/bot IDs and an `X` token, not a credential. Allowlisted in `.gitleaksignore`. | mdarguechi | 2027-02-12 |
| trivy AVD-DS-0002 (no `USER`) | `Dockerfile`, `.ci/Dockerfile` | The runtime image must attach TC/BPF programs, which needs root with CAP_BPF/CAP_NET_ADMIN (the compose file runs it privileged). `.ci/Dockerfile` is a throwaway build container. | mdarguechi | 2027-02-12 |
| gosec G204 | `internal/network/utils.go:244,284` | `exec.Command` with a fixed program and argv (no shell); the variable is an interface name read from the kernel. | mdarguechi | 2027-02-12 |
| gosec G304 | `internal/databases/mac.go` (cache reads) | Paths are under `CERBERUS_DATA_DIR`, set by the operator who already runs the process as root. | mdarguechi | 2027-02-12 |
| gosec G115 | `internal/databases/service.go:176` | Values come from `strconv.ParseUint(..., 10, 16)`, so the `uint16` conversion cannot overflow. | mdarguechi | 2027-02-12 |
| gosec G104 | `internal/monitor/monitor.go:88-89,447-455,797-805`, `internal/network/utils.go:254` | Ignored errors on best-effort index creation and cache persistence. No security impact; tracked as a reliability follow-up. | mdarguechi | 2027-02-12 |
