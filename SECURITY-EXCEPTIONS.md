# Security exceptions

Scanner findings that are accepted rather than fixed. Each entry has an
owner and a review date no more than 90 days out.

| ID | Where | Why it is acceptable | Owner | Review by |
|----|-------|----------------------|-------|-----------|
| gitleaks `slack-webhook-url` | `configs/alerts.notifications.yaml:24` (since 44cc54e) | Documentation placeholder with all-zero team/bot IDs and an `X` token, not a credential. Allowlisted in `.gitleaksignore`. | mdarguechi | 2027-02-12 |
| trivy AVD-DS-0002 (no `USER`) | `Dockerfile`, `.ci/Dockerfile` | The runtime image must attach TC/BPF programs, which needs root with CAP_BPF/CAP_NET_ADMIN (the compose file runs it privileged). `.ci/Dockerfile` is a throwaway build container. | mdarguechi | 2027-02-12 |
