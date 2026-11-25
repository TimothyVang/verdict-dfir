"""ACH worker pools — Pool A (persistence) + Pool B (exfiltration).

Spec #2 §4.2 + §8.1. Each pool has the same investigation graph
internals; the difference is the system prompt fragment injected
into every specialist subagent. Pool A's prompt biases the agents
toward persistence tradecraft (Scheduled Tasks, Services, WMI,
Run keys, IFEO, LOLBins). Pool B biases toward exfiltration (net
connections, staging dirs, certutil, bitsadmin, cloud sync, USB
writes).

Both pools share the same Claude model — heterogeneous model
strength is forbidden by Spec #2 §8.2 because Estornell ICML 2025
documented the weak-agent poisoning failure.
"""

from findevil_agent.pools.exfil import EXFIL_SYSTEM_PROMPT, ExfilPool
from findevil_agent.pools.persistence import PERSISTENCE_SYSTEM_PROMPT, PersistencePool

__all__ = [
    "EXFIL_SYSTEM_PROMPT",
    "PERSISTENCE_SYSTEM_PROMPT",
    "ExfilPool",
    "PersistencePool",
]
