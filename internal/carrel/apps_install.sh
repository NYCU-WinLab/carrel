#!/bin/sh
# Installs carrel-deployd for one app (PLAN 7.9). Run by the machine owner:
#   f=$(mktemp) && curl -fsSL @ORIGIN@/apps/v1/install.sh -o "$f" && sudo sh "$f" --app NAME --port N --user USER --start CMD; rm -f "$f"
# The agent token comes on standard input, never in a command line that ps or
# a shell history keeps (issue #33): piped through ssh from the client
# (printf '%s\n' TOKEN | ssh host '<line>'), or pasted at the prompt.
# CARREL_APP_TOKEN in the environment still works for older install lines.
set -eu

app="" port="" user="" start=""
while [ $# -gt 0 ]; do
	case "$1" in
	--app) app="$2"; shift 2 ;;
	--port) port="$2"; shift 2 ;;
	--user) user="$2"; shift 2 ;;
	--start) start="$2"; shift 2 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
if [ -z "${CARREL_APP_TOKEN:-}" ]; then
	[ -t 0 ] && printf 'carrel agent token: ' >&2
	IFS= read -r CARREL_APP_TOKEN || true
fi
# A token pasted from Windows ends in CR.
CARREL_APP_TOKEN=$(printf '%s' "${CARREL_APP_TOKEN:-}" | tr -d '\r')
# One line of the token's alphabet only: it also cannot break out of the JSON below.
case "$CARREL_APP_TOKEN" in
cdt_*) ;;
*) echo "the agent token (cdt_...) is required on standard input" >&2; exit 1 ;;
esac
case "${CARREL_APP_TOKEN#cdt_}" in
"" | *[!A-Za-z0-9_-]*) echo "the agent token (cdt_...) is malformed" >&2; exit 1 ;;
esac
echo "$app" | grep -Eq '^[a-z][a-z0-9-]{0,31}$' || { echo "invalid --app" >&2; exit 1; }
echo "$port" | grep -Eq '^[0-9]{1,5}$' || { echo "invalid --port" >&2; exit 1; }
[ -n "$start" ] || { echo "--start is required" >&2; exit 1; }
id "$user" >/dev/null 2>&1 || { echo "unknown --user" >&2; exit 1; }
[ "$user" != root ] || { echo "run the app as a normal user" >&2; exit 1; }

tmp=$(mktemp)
curl -fsSL -o "$tmp" "@ORIGIN@/apps/v1/carrel-deployd"
install -m 0755 "$tmp" /usr/local/bin/carrel-deployd
rm -f "$tmp"

install -d -m 0700 /etc/carrel-deployd
umask 077
cat >"/etc/carrel-deployd/$app.json" <<JSON
{"origin": "@ORIGIN@", "token": "$CARREL_APP_TOKEN", "app": "$app", "port": $port, "user": "$user"}
JSON
umask 022
# The app user reads the start command, so it lives outside the 0700 token directory.
install -d -m 0755 /etc/carrel-app
printf '%s\n' "$start" >"/etc/carrel-app/$app.start"
chmod 0644 "/etc/carrel-app/$app.start"
rm -f "/etc/carrel-deployd/$app.start"

install -d -o "$user" -g "$(id -gn "$user")" -m 0755 "/srv/apps/$app" "/srv/apps/$app/releases"
if [ ! -e "/srv/apps/$app/env" ]; then
	install -o "$user" -g "$(id -gn "$user")" -m 0600 /dev/null "/srv/apps/$app/env"
fi

cat >"/etc/systemd/system/carrel-app-$app.service" <<UNIT
[Unit]
Description=carrel app $app
After=network-online.target
Wants=network-online.target
ConditionPathExists=/srv/apps/$app/current

[Service]
User=$user
WorkingDirectory=/srv/apps/$app/current
Environment=PORT=$port
EnvironmentFile=-/srv/apps/$app/env
ExecStart=/bin/sh /etc/carrel-app/$app.start
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/carrel-deployd@.service <<'UNIT'
[Unit]
Description=carrel deploy agent for %i
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/carrel-deployd -config /etc/carrel-deployd/%i.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "carrel-app-$app.service" >/dev/null 2>&1
systemctl enable --now "carrel-deployd@$app.service"
systemctl restart "carrel-deployd@$app.service"
echo "carrel-deployd is running for $app. Push to the linked branch to deploy."
