# Host runbook — operator only

Run these steps on the host, **outside every Otto pipeline stage**, from
your Atlas checkout, after landing. Replace `<ATLAS_DIR>` and disposable target
names with the actual installation and reviewed targets. Nothing in this runbook
is run by the implementation pipeline. Keep Otto's Host control actions toggle off
until step 5. Use a private shell; do not print the bearer token or enable shell tracing.

1. **Deploy with actions off.** Run `go build -o atlas-agent ./cmd/atlas-agent` and
   install the binary using the existing deployment procedure, preserving the
   previous binary for rollback. Ensure `ATLAS_ACTIONS` is unset or empty, then run
   `sudo systemctl restart atlas.service`. Verify `systemctl is-active atlas.service`.
   Load the token into `T` privately and verify the disabled endpoint without putting
   the token in curl's argv:

   ```bash
   printf 'Authorization: Bearer %s\n' "$T" | curl --header @- --silent --output /dev/null --write-out '%{http_code}\n' --request POST http://<TAILNET_IP>:7788/api/actions --data '{}'
   ```

   Expect 404. Rollback: reinstall the previous binary and restart Atlas. Preserve
   `<ATLAS_DIR>/atlas-audit.log` and `<ATLAS_DIR>/atlas-actions/` on every rollback,
   deployment and backup. Never change `ATLAS_ACTION_DIR` without migrating the entire
   directory: ids and unresolved operations must survive agent restarts.

2. **Install the fixed apt unit, only if apt actions are wanted.** Review the two
   exact `ExecStart` commands in `atlas-apt-upgrade.service`. Run:

   ```bash
   sudo install -m 0644 deploy/actions/atlas-apt-upgrade.service /etc/systemd/system/
   sudo systemctl daemon-reload
   systemctl cat atlas-apt-upgrade.service
   systemctl show atlas-apt-upgrade.service -p LoadState -p ActiveState -p ExecStart -p Environment
   ```

   Verify loaded/inactive, the two commands, and `DEBIAN_FRONTEND=noninteractive`.
   Do not enable or start the unit for this installation check. Atlas verifies its
   loaded identity, oneshot type, commands, environment and absence of additional
   execution hooks/environment files before each approval. It runs outside Atlas's
   `ProtectSystem=strict` sandbox and survives an Atlas restart. Its own 30-minute
   systemd limit can interrupt a slow package operation; after any timeout inspect
   the journal and package-manager state before retrying.
   Rollback, only after any upgrade has finished: remove this new unit file and run
   `sudo systemctl daemon-reload`. Package changes already made are not undone.

3. **Grant narrow systemd permissions.** Copy `50-atlas-actions.rules` to a temporary
   file, set `restartUnits` to explicit harmless `.service` names (initially just a
   disposable test unit), and match `subject.user` to Atlas's service user. Leave
   `allowApt=false` unless step 2 is complete and apt is wanted. Keep `aptUnit` in sync
   with `ATLAS_APT_UNIT` if using a different name. Leave `allowMaintenance=false`
   unless the reviewed `otto-maint-backup-unlock.service` / `otto-maint-backup-cache-dir.service`
   oneshots (from Otto's `docs/HOST_ACTIONS.md`) are installed and `run-maintenance` is
   wanted; never add other units to `maintenanceUnits`. Include Atlas's actual unit name
   in `protectedUnits` if it differs from `atlas.service`.

   ```bash
   sudo install -m 0644 <REVIEWED_RULE_FILE> /etc/polkit-1/rules.d/50-atlas-actions.rules
   journalctl -u polkit -n 20 --no-pager
   sudo -u atlas systemctl --no-ask-password restart <DISPOSABLE>.service
   ```

   polkit reloads rules automatically. Verify no rule syntax errors and that only
   the disposable unit restarted. Test denied authorizations **without dispatching
   a protected restart**:

   ```bash
   sudo -u atlas sh -c 'pkcheck --action-id org.freedesktop.systemd1.manage-units --process "$$" --detail unit otto.service --detail verb restart'
   sudo -u atlas sh -c 'pkcheck --action-id org.freedesktop.systemd1.manage-units --process "$$" --detail unit apt-daily.service --detail verb start'
   ```

   Both must exit nonzero; a zero result means some policy is too broad. Do not
   enable controls until that is resolved. Rollback: remove only
   `/etc/polkit-1/rules.d/50-atlas-actions.rules`, then use the same `pkcheck` form for
   the previously allowed disposable restart and verify it is denied.

4. **Enable only the selected Atlas actions.** Copy `atlas-actions.conf` to a temporary
   file and replace `<ATLAS_DIR>`. Set comma-separated `ATLAS_ACTIONS` (for example
   `restart-unit`) and the corresponding exact allowlist (`ATLAS_RESTART_UNITS`,
   `ATLAS_RESTART_CONTAINERS`, or `ATLAS_KILL_USERS`). Empty allowlists refuse every
   request. `apt-upgrade` requires the reviewed unit and polkit grant from steps 2–3;
   `run-maintenance` requires the installed `otto-maint-*` units and `allowMaintenance`.
   Keep kill disabled unless intentionally granting `AmbientCapabilities=CAP_KILL`
   and explicit non-root users. Never grant wildcard sudo kill access. Docker actions
   use the existing local Docker socket grant; it is already powerful and is not
   narrowed by this endpoint's allowlist for other programs running as Atlas.

   ```bash
   sudo install -d /etc/systemd/system/atlas.service.d
   sudo install -m 0644 <REVIEWED_DROPIN_FILE> /etc/systemd/system/atlas.service.d/50-atlas-actions.conf
   sudo systemctl daemon-reload
   sudo systemctl restart atlas.service
   systemctl is-active atlas.service
   journalctl -u atlas.service -n 20 --no-pager
   ```

   Verify the startup log lists only the intended kinds and has no empty-allowlist
   warning. The action directory must be writable inside Atlas's `ReadWritePaths`, and its
   parent directory must already exist.
   Rollback: remove **only** `50-atlas-actions.conf`, run daemon-reload and restart
   Atlas; verify the endpoint returns 404. Do not use `systemctl revert`, which would
   also remove unrelated operator drop-ins. Keep the audit and action directory.

5. **Test end to end as the operator.** In Otto Settings › Home server, enable **Host control
   actions**. Request a disposable restart, inspect the exact command, and approve.
   Verify Otto reports done/exit 0, its Host action history contains the request id,
   and Atlas's audit has `action.received`, `action.executing`, `action.completed`
   with the same id. Decline a second request and verify nothing reached Atlas.
   Request a protected target and verify refusal without a host mutation. Check
   a missing privilege gives a completed failure rather than success. These manual
   tests, and any shared-database end-to-end suite, belong outside pipeline stages.
   Rollback: turn Otto's toggle off, roll back step 4, and inspect any already
   dispatched action before doing more work. Disabling controls does not cancel it.

## Unknown outcomes and recovery

Atlas waits up to 85 seconds for restarts, 10 seconds for SIGTERM, and 29 minutes for
apt (including live preflight). HTTP action connections allow 31 minutes. The agent
waits up to 80 seconds during shutdown; an apt reply can be lost while the separate
apt unit continues. Docker or systemd transport failures can also leave an operation
running after the reply. Never retry an unknown result automatically.

`<ATLAS_DIR>/atlas-actions/active.json` is a durable interlock shared by all instances
using that directory. It remains after a crash, unknown outcome, or completion-audit
failure. All further actions return 409 until the operator reconciles it. A crash
between creating the marker and dispatch can leave it even if nothing ran.

On the host, first disable Otto's toggle and set `ATLAS_ACTIONS=` in the
specific Atlas drop-in; daemon-reload and restart Atlas. Inspect the marker's `id`
and `kind` privately, the corresponding audit entries, and host state:

```bash
systemctl list-jobs
systemctl show <TARGET_UNIT> -p ActiveState -p Result -p ExecMainStatus -p InvocationID
journalctl -u <TARGET_UNIT> --no-pager -n 100
# For a container action instead:
docker inspect --format '{{.Id}} {{.State.Status}} {{.State.StartedAt}}' <TARGET_CONTAINER>
```

For SIGTERM, inspect the recorded process identity and current `/proc/<pid>`; never
signal a reused numeric pid as recovery. For apt, ensure no apt/dpkg job is still
running and investigate any interrupted transaction manually. Only after the
outcome is resolved and nothing is still running, archive `active.json` beside the
retained audit and then remove **only that marker**, e.g.:

```bash
sudo cp --preserve=mode,ownership <ATLAS_DIR>/atlas-actions/active.json <PRIVATE_ARCHIVE_PATH>
sudo rm <ATLAS_DIR>/atlas-actions/active.json
```

Record the resolution with the request id in the operator's incident notes. Verify
all `<id>.json` reservation files remain. Restore the reviewed action configuration,
daemon-reload/restart Atlas, then restore Otto's toggle. If recovery is uncertain,
leave the marker and controls off; no destructive cleanup is required.
