# TelsonBase

> *"Trust and audit are not features. They are the condition under which all other features are permitted to run."*

---

## What This Is

`TelsonBase` is the trust and governance layer of the DispatcherAgents architecture.

It governs **what agents are permitted to do** -- not how they think (agent-open-mind),
not whether they are aligned with their own reasoning (open-mind), not whether they
maintain context across sessions (sleep-marks). Those tools operate inside the trust
boundary TelsonBase defines.

TelsonBase is the boundary.

---

## Why It Exists

A dispatcher can read its agents' thoughts.
A dispatcher can compare its thinking to its response.
A dispatcher can restore its reasoning context after a break.

None of that matters if the dispatcher cannot be trusted to operate within defined limits.

The cognitive tools are powerful precisely because they give agents more visibility into
their own and others' reasoning. Power without governance is the failure mode TelsonBase
is designed to prevent.

---

## Architecture Position

```
DispatcherAgents
|
+-- TelsonBase          <- governs WHAT agents are permitted to do (you are here)
|
+-- before-turn         <- governs HOW agents enter each response
|
+-- agent-open-mind     <- captures HOW agents think (sub-agents and self)
|
+-- open-mind           <- aligns thinking to response (drift detection)
|
+-- sleep-marks         <- restores reasoning state across sessions
```

TelsonBase sits at the root. It does not depend on the other tools.
The other tools operate within the trust model TelsonBase defines.

---

## What TelsonBase Governs (v0.1 Scope)

**Permissions** -- What operations is an agent permitted to perform?
Which file paths. Which commands. Which external services. Which other agents.

**Audit** -- What did the agent do, when, and with what authorization?
Immutable log of agent actions within the governed boundary.

**Trust levels** -- What is the trust level of each agent in the dispatcher's graph?
Verified, unverified, sandboxed, trusted-with-review.

**Escalation** -- What happens when an agent attempts an operation outside its permission scope?
Halt, log, escalate to human, or request expanded permission explicitly.

---

## Why TelsonBase Is Named

The telson is the terminal segment of an arthropod -- the rearmost structural element
that defines the boundary of the organism. In a scorpion, it carries the sting.
In a lobster, it is the fan that controls direction.

TelsonBase is the boundary segment. It defines the edge of what the dispatcher is.
Without it, the organism has no defined limits.

---


## v0.1 Roadmap

- [ ] Permission schema definition (YAML or JSON)
- [ ] Agent registration and trust level assignment
- [ ] Audit log format (append-only, tamper-evident)
- [ ] Escalation handler interface
- [ ] Integration hooks for agent-open-mind (read traces within permission scope)
- [ ] Integration hooks for before-turn (verify protocol compliance)

---

## Part of the DispatcherAgents Family

Part of the [DispatcherAgents](https://dispatcheragents.com) project by [QuietFireAI](https://github.com/QuietFireAI).

---

## License

Apache 2.0 - QuietFireAI / [dispatcheragents.com](https://dispatcheragents.com)
