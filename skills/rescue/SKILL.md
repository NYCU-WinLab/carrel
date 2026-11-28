---
name: rescue
description: Use when a member cannot get into a machine over SSH. Read the console log first, then reset access with new keys.
version: 1.0.1
requires_tools: [machine_get, machine_reset_access]
verified:
---

# Rescue: "I cannot get in"

1. Call `machine_get` with the machine name. Check that the machine is running and note its kind.
2. Check that the machine booted before touching keys: a boot failure, a full disk or a stuck cloud-init
   will not be fixed by new keys. (A read-only console log tool, `machine_console_log`, is planned in
   PLAN 7.6; use it here once the contract has it.) If the machine did not boot, fix that first.
3. If the machine booted but accepts none of the member's keys, call `machine_reset_access` with
   `confirm` set to the machine name. Use `dry_run` first when the member is unsure.
   - Only a VM that carrel configures through cloud-init takes new keys. A CT, a machine installed
     from an ISO and a machine that serves its own ports do not.
   - The reset shuts the VM down and starts it again. Warn the member before a running VM restarts.
   - Keys already on the machine stay. A key with `command=` or `from=` options comes back without
     them.
4. Wait for the operation to succeed, then check the connection with `ssh` using the alias from
   `machine_get`.

## Host key warning

The reset keeps the SSH host keys, so clients normally see no warning. If the member still gets a
host key warning, the machine was rebuilt or its address was reused. Check with `machine_get`, then
have the member remove the old entry with `ssh-keygen -R <host>`. Never disable host key checking.
