#!/bin/sh
# carrel runner install (issue #267): installs, or with --remove removes, a
# GitHub Actions or GitLab self-hosted runner on this machine. The runner
# token comes in on standard input, so no command line carries it. Jobs run
# as the unprivileged user carrel-runner, never as root.
# Served by carrel at /apps/v1/runner.sh; runner_add gives the full line.
set -eu
provider= url= name= labels= remove=
while [ $# -gt 0 ]; do
  case "$1" in
  --provider) provider=$2; shift 2 ;;
  --url) url=$2; shift 2 ;;
  --name) name=$2; shift 2 ;;
  --labels) labels=$2; shift 2 ;;
  --remove) remove=1; shift ;;
  *) echo "carrel: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "carrel: run with sudo." >&2; exit 1; }
case "$provider" in github | gitlab) ;; *) echo "carrel: --provider must be github or gitlab." >&2; exit 2 ;; esac
case "$name" in '' | *[!A-Za-z0-9._-]*) echo "carrel: --name must be letters, digits, '.', '_' or '-'." >&2; exit 2 ;; esac

user=carrel-runner
home=/var/lib/carrel-runner
case "$(uname -m)" in
x86_64) gh_arch=x64; gl_arch=amd64 ;;
aarch64 | arm64) gh_arch=arm64; gl_arch=arm64 ;;
*) echo "carrel: unsupported architecture $(uname -m)." >&2; exit 1 ;;
esac

# read_token reads one line from standard input, or asks on the terminal.
read_token() {
  if [ -t 0 ]; then
    printf 'Runner token: ' >&2
    stty -echo 2>/dev/null || true
    IFS= read -r token || true
    stty echo 2>/dev/null || true
    echo >&2
  else
    IFS= read -r token || true
  fi
  case "$token" in '' | null) echo "carrel: no runner token on standard input." >&2; exit 1 ;; esac
}

need() {
  missing=
  for tool in "$@"; do command -v "$tool" >/dev/null || missing="$missing $tool"; done
  if [ -n "$missing" ]; then
    command -v apt-get >/dev/null || { echo "carrel: install$missing first." >&2; exit 1; }
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $missing ca-certificates >/dev/null
  fi
}

ensure_user() {
  id "$user" >/dev/null 2>&1 || useradd --system --create-home --home-dir "$home" --shell /bin/bash "$user"
  # Debian's .bash_logout runs clear_console, which fails without a
  # terminal and fails every GitLab shell job with it.
  rm -f "$home/.bash_logout"
}

github_install() {
  need curl jq tar git
  ensure_user
  dir=/opt/carrel-runner/$name
  [ ! -e "$dir/.runner" ] || { echo "carrel: runner $name is already configured in $dir; remove it first." >&2; exit 1; }
  version=$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest | jq -r .tag_name | sed 's/^v//')
  mkdir -p "$dir"
  curl -fsSL "https://github.com/actions/runner/releases/download/v$version/actions-runner-linux-$gh_arch-$version.tar.gz" | tar xz -C "$dir"
  "$dir/bin/installdependencies.sh" >/dev/null
  chown -R "$user:$user" "$dir"
  # The runner reads any config.sh argument from ACTIONS_RUNNER_INPUT_<NAME>;
  # an environment variable, unlike an argument, is not visible in ps.
  (cd "$dir" && ACTIONS_RUNNER_INPUT_TOKEN=$token HOME=$home runuser -p -u "$user" -- \
    ./config.sh --unattended --url "$url" --name "$name" --labels "${labels:-carrel}" --replace --disableupdate)
  (cd "$dir" && ./svc.sh install "$user" >/dev/null && ./svc.sh start >/dev/null)
  echo "Runner $name is online for $url."
}

github_remove() {
  dir=/opt/carrel-runner/$name
  [ -d "$dir" ] || { echo "Runner $name is not on this machine."; return 0; }
  if [ -f "$dir/svc.sh" ] && [ -f "$dir/.service" ]; then
    (cd "$dir" && ./svc.sh stop >/dev/null 2>&1 || true; ./svc.sh uninstall >/dev/null 2>&1 || true)
  fi
  if [ -e "$dir/.runner" ]; then
    (cd "$dir" && ACTIONS_RUNNER_INPUT_TOKEN=$token HOME=$home runuser -p -u "$user" -- ./config.sh remove --unattended)
  fi
  rm -rf "$dir"
  echo "Runner $name is removed."
}

gitlab_install() {
  need curl
  ensure_user
  if [ ! -x /usr/local/bin/gitlab-runner ]; then
    curl -fsSL -o /usr/local/bin/gitlab-runner "https://gitlab-runner-downloads.s3.amazonaws.com/latest/binaries/gitlab-runner-linux-$gl_arch"
    chmod 755 /usr/local/bin/gitlab-runner
  fi
  instance=$(printf '%s' "$url" | sed -E 's#^(https://[^/]+).*#\1#')
  # register reads the runner token from CI_SERVER_TOKEN.
  CI_SERVER_TOKEN=$token /usr/local/bin/gitlab-runner register --non-interactive \
    --url "$instance" --executor shell --name "$name" >/dev/null
  [ -f /etc/systemd/system/gitlab-runner.service ] ||
    /usr/local/bin/gitlab-runner install --user "$user" --working-directory "$home"
  systemctl enable --now gitlab-runner >/dev/null
  systemctl restart gitlab-runner
  echo "Runner $name is online for $instance."
}

gitlab_remove() {
  # Removing twice is not an error: the client deletes the runner on GitLab
  # after this, and a retry must reach that step.
  if [ -x /usr/local/bin/gitlab-runner ] && grep -qF "name = \"$name\"" /etc/gitlab-runner/config.toml 2>/dev/null; then
    /usr/local/bin/gitlab-runner unregister --name "$name"
  fi
  echo "Runner $name is removed from this machine."
}

token=
if [ -n "$remove" ]; then
  [ "$provider" = gitlab ] || read_token
  "${provider}_remove"
else
  [ -n "$url" ] || { echo "carrel: give --url." >&2; exit 2; }
  read_token
  "${provider}_install"
fi
