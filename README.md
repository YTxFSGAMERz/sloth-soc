# Sloth SOC

An offline "lazy security analyst". Every night it reads server logs (sshd, nginx, fail2ban, ufw), finds what matters with rules, statistics, and ML, and has a local open-weight LLM (Gemma via Ollama) write a short morning digest.

**Principle: math decides, the LLM only narrates.**
