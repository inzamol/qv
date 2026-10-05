# 🐳 Docker Container Issues Example

This example demonstrates common container configuration antipatterns and security issues detected by `qv`.

---

## 🔍 Issues Triggered

| Rule ID | Severity | Description | Line in Dockerfile |
| :--- | :--- | :--- | :--- |
| **`DOC-001`** | `WARNING` | Inefficient layer caching: `COPY . .` executed before `RUN pip install`. | Line 6 |
| **`DOC-002`** | `WARNING` | Root user container execution: `CMD` defined without non-root `USER`. | Line 10 |
| **`DOC-003`** | `INFO` | Unpinned base image tag: `FROM python:latest`. | Line 1 |
| **`DOC-004`** | `WARNING` | Missing `.dockerignore` file in project repository. | Project Root |
| **`DOC-005`** | `INFO` | Missing `--no-cache-dir` in `pip install`. | Line 8 |
| **`DOC-006`** | `ERROR` | Sensitive file copied: `COPY .env /app/.env`. | Line 5 |

---

## 🚀 How to Run

```bash
# Run Docker checks only
qv docker examples/docker_issues

# Run full project scan
qv scan examples/docker_issues

# Run doctor scorecard
qv doctor examples/docker_issues
```
