# Kubernetes Security Attack Scripts

This repository contains a set of Python scripts used to simulate common Kubernetes attack scenarios over a multi-day hardening exercise.  The goal is to demonstrate how various security controls (NetworkPolicy, RBAC, PodSecurity, etc.) mitigate specific threats.

## Contents

- `attack_1.py` – Day 1 attacks: assumes the attacker is outside the pod.  Shows metadata access, secret enumeration, and external egress.  Hardening focuses on NetworkPolicy and RBAC.
- `attack_2.py` – Day 2 attacks: repeats Day 1 and adds container escape techniques.  Demonstrates why PodSecurity (restricted) and removal of host privileges are important.
- `attack_3.py` – (presumably) Day 3 attacks: further escalation, lateral movement, etc.

## Usage

Each script accepts a `--rce-url` argument pointing at an HTTP endpoint that can execute arbitrary commands (the "phoenix" service in the original exercise).

```bash
python3 attack_1.py --rce-url http://<phoenix-endpoint>/<secret-path>/
python3 attack_2.py --rce-url http://<phoenix-endpoint>/<secret-path>/
# etc.
```

The scripts print coloured banners and provide summaries indicating which attacks succeeded or were blocked, illustrating the effectiveness of different security layers.

## Requirements

- Python 3
- `requests` package (install via `pip install requests`)

## License

[Add your preferred license here]
