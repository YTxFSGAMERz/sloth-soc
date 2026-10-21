# Third-Party Software and Model Licenses

This document outlines the licensing terms for the Sloth SOC codebase, its open-source dependencies, and the open-weight LLM models supported by the narration engine.

---

## 1. Sloth SOC License
Sloth SOC is released under the **MIT License**.

```text
Copyright (c) 2026 Sloth SOC Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 2. Core Python Dependencies

| Package | License | Project URL / Source |
|---|---|---|
| **Pydantic** | MIT License | https://github.com/pydantic/pydantic |
| **Typer** | MIT License | https://github.com/fastapi/typer |
| **Rich** | MIT License | https://github.com/Textualize/rich |
| **HTTPX** | BSD 3-Clause License | https://github.com/encode/httpx |
| **PyYAML** | MIT License | https://github.com/yaml/pyyaml |
| **Jinja2** | BSD 3-Clause License | https://github.com/pallets/jinja |
| **Pandas** | BSD 3-Clause License | https://github.com/pandas-dev/pandas |
| **Scikit-learn** | BSD 3-Clause License | https://github.com/scikit-learn/scikit-learn |
| **SciPy** | BSD 3-Clause License | https://github.com/scipy/scipy |
| **Matplotlib** | Matplotlib License (BSD-compatible) | https://github.com/matplotlib/matplotlib |
| **Hypothesis** | Mozilla Public License 2.0 (MPL-2.0) | https://github.com/HypothesisWorks/hypothesis |
| **Pytest** | MIT License | https://github.com/pytest-dev/pytest |
| **Ruff** | MIT License | https://github.com/astral-sh/ruff |

---

## 3. Supported Model Terms of Use

Sloth SOC interfaces with locally deployed open-weight models via Ollama. It does not distribute model weights directly.

### Gemma Open Models (Google DeepMind)
- **Models:** `gemma4:e4b`, `gemma4:e2b`, `gemma2:2b`, `gemma:2b`
- **License / Terms:** Subject to the official [Gemma Terms of Use](https://ai.google.dev/gemma/terms).
- **Compliance:** Gemma weights are downloaded by the end-user locally on their own machines via the Ollama client (`ollama pull gemma4:e4b`). Sloth SOC runs completely offline and does not transmit prompt or weight data to Google or any remote cloud service.
