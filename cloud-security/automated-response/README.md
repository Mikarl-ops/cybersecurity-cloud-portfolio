# GuardDuty response simulation

## Purpose

This small Python example reads the severity and resource type from a GuardDuty-style event and logs a proposed response for selected high-severity EC2 or IAM findings.

## Current behavior

The functions only log simulated actions and return success. They do not call AWS, isolate an instance, revoke credentials, publish an alert, or measure response time. The included sample event is synthetic. Treat the code as a response-planning demonstration, not an operational SOAR integration.

## Next steps

A fuller lab could add typed event fixtures, a dry-run response plan, unit tests for supported event types, and a separately permissioned AWS adapter. Any live containment action should have explicit scope, audit logging, and a rollback procedure.
