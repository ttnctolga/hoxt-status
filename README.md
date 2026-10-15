# hoxt-status

Public status monitor for Hoxt services (status.hoxt.net).

It publishes only: service name, status and time. No server addresses, internal host names,
error details or logs are ever published; `public_gate.py` enforces this on every run and
blocks publishing on any violation.
