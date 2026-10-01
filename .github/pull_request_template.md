## 📝 Description

Briefly describe the changes introduced in this Pull Request, including the problem solved or feature added.

---

## 🔗 Related Issues

- Fixes #(issue)
- Closes #(issue)

---

## 🧪 Type of Change

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature / rule (non-breaking change which adds new diagnostic or visualizer)
- [ ] ⚡ Performance improvement
- [ ] 📖 Documentation update
- [ ] 🧹 Refactoring or code quality cleanup

---

## ✅ Quality Checklist

- [ ] I have read the [Contributing Guidelines](https://github.com/inzamol/qv/blob/main/docs/contributing.md).
- [ ] My code adheres to strict type annotations and passes `uv run pyright`.
- [ ] My code passes linting and formatting via `uv run ruff check .` and `uv run ruff format --check .`.
- [ ] I have added comprehensive unit tests covering positive and negative cases under `tests/`.
- [ ] All tests pass locally with `uv run pytest`.
- [ ] Multi-environment matrix passes locally with `uv run tox`.
- [ ] If adding a new rule or CLI option, I have updated the relevant documentation in `docs/` and `README.md`.
