#!/usr/bin/env bash
set -euo pipefail

COMMAND="${1:-status}"
REMOTE_ROOT="${WASP_REMOTE_ROOT:-${WASP_REMOTE_SCRATCH:-/scratch0/$USER/wasp}}"
RUNTIME="${WASP_CONTAINER_RUNTIME:-auto}"
GITLAB_IMAGE="${WASP_GITLAB_IMAGE:-gitlab-populated-final-port8023}"
REDDIT_IMAGE="${WASP_REDDIT_IMAGE:-postmill-populated-exposed-withimg}"
GITLAB_PORT="${WASP_GITLAB_REMOTE_PORT:-8023}"
REDDIT_PORT="${WASP_REDDIT_REMOTE_PORT:-9999}"
PUBLIC_GITLAB_URL="${WASP_PUBLIC_GITLAB_URL:-http://127.0.0.1:18023}"
GITLAB_URL="${WASP_GITLAB_DOWNLOAD_URL:-http://metis.lti.cs.cmu.edu/webarena-images/gitlab-populated-final-port8023.tar}"
REDDIT_URL="${WASP_REDDIT_DOWNLOAD_URL:-http://metis.lti.cs.cmu.edu/webarena-images/postmill-populated-exposed-withimg.tar}"
GITLAB_TAR="${WASP_GITLAB_TAR:-$REMOTE_ROOT/images/gitlab-populated-final-port8023.tar}"
REDDIT_TAR="${WASP_REDDIT_TAR:-$REMOTE_ROOT/images/postmill-populated-exposed-withimg.tar}"
GITLAB_SANDBOX="${WASP_GITLAB_SANDBOX:-$REMOTE_ROOT/singularity/gitlab-pristine}"
REDDIT_SANDBOX="${WASP_REDDIT_SANDBOX:-$REMOTE_ROOT/singularity/reddit-pristine}"
GITLAB_ACTIVE="$REMOTE_ROOT/active/gitlab"
REDDIT_ACTIVE="$REMOTE_ROOT/active/reddit"
GITLAB_INSTANCE="wasp-gitlab"
REDDIT_INSTANCE="wasp-forum"

export SINGULARITY_CACHEDIR="${SINGULARITY_CACHEDIR:-$REMOTE_ROOT/cache/singularity}"
export SINGULARITY_TMPDIR="${SINGULARITY_TMPDIR:-$REMOTE_ROOT/tmp}"

mkdir -p "$REMOTE_ROOT/images" "$REMOTE_ROOT/singularity" \
	"$REMOTE_ROOT/active" "$SINGULARITY_CACHEDIR" "$SINGULARITY_TMPDIR"

case "$COMMAND" in
	download|prepare|start|reset)
		exec 9>"$REMOTE_ROOT/environment.lock"
		flock 9
		;;
esac

if [ "$RUNTIME" = auto ]; then
	if command -v docker >/dev/null 2>&1; then
		RUNTIME=docker
	elif command -v singularity >/dev/null 2>&1; then
		RUNTIME=singularity
	else
		echo "Neither Docker nor Singularity is installed on this host." >&2
		exit 3
	fi
fi

if ! command -v "$RUNTIME" >/dev/null 2>&1; then
	echo "Container runtime '$RUNTIME' is not installed on this host." >&2
	exit 3
fi

download_if_needed() {
	local archive="$1"
	local url="$2"
	local partial="${archive}.part"
	local resume=()
	if [ -s "$archive" ]; then
		echo "Archive already present: $archive"
		return
	fi
	echo "Downloading $url"
	if [ -f "$partial" ]; then
		resume=(--continue-at -)
	fi
	curl --fail --location --retry 8 --retry-delay 15 "${resume[@]}" \
		--output "$partial" "$url"
	mv "$partial" "$archive"
}

download_archives() {
	download_if_needed "$GITLAB_TAR" "$GITLAB_URL" &
	gitlab_download=$!
	download_if_needed "$REDDIT_TAR" "$REDDIT_URL" &
	reddit_download=$!
	wait "$gitlab_download"
	wait "$reddit_download"
}

docker_load_if_needed() {
	local image="$1"
	local archive="$2"
	if "$RUNTIME" image inspect "$image" >/dev/null 2>&1; then
		return
	fi
	[ -s "$archive" ] || { echo "Missing archive: $archive" >&2; exit 4; }
	"$RUNTIME" load --input "$archive"
	"$RUNTIME" image inspect "$image" >/dev/null
}

build_sandbox_if_needed() {
	local archive="$1"
	local sandbox="$2"
	local temporary="${sandbox}.building"
	if [ -f "$sandbox/.singularity.d/runscript" ]; then
		echo "Pristine sandbox already present: $sandbox"
		return
	fi
	[ -s "$archive" ] || { echo "Missing archive: $archive" >&2; exit 4; }
	rm -rf "$temporary"
	echo "Building writable Singularity sandbox from $archive"
	singularity build --fakeroot --fix-perms --sandbox "$temporary" \
		"docker-archive://$archive"
	mv "$temporary" "$sandbox"
}

prepare_environment() {
	download_archives
	if [ "$RUNTIME" = docker ]; then
		docker_load_if_needed "$GITLAB_IMAGE" "$GITLAB_TAR"
		docker_load_if_needed "$REDDIT_IMAGE" "$REDDIT_TAR"
	else
		build_sandbox_if_needed "$GITLAB_TAR" "$GITLAB_SANDBOX"
		build_sandbox_if_needed "$REDDIT_TAR" "$REDDIT_SANDBOX"
	fi
}

remove_docker_container() {
	local name="$1"
	"$RUNTIME" stop "$name" >/dev/null 2>&1 || true
	"$RUNTIME" rm "$name" >/dev/null 2>&1 || true
}

stop_singularity_instance() {
	local name="$1"
	singularity instance stop "$name" >/dev/null 2>&1 || true
}

clone_sandbox() {
	local pristine="$1"
	local active="$2"
	rm -rf "$active"
	mkdir -p "$active"
	# The validated remote scratch volume supports XFS reflinks: this creates a
	# cheap writable reset while preserving a pristine benchmark image.
	cp --archive --reflink=always "$pristine/." "$active/"
}

normalize_active_sandbox_for_removal() {
	local pristine="$1"
	local active="$2"
	[ -d "$active" ] || return 0
	# Service-account ownership created inside single-ID fakeroot can otherwise
	# make a stopped active sandbox undeletable by the host account. Use the
	# pristine image only as a helper rootfs and normalize the disposable clone.
	singularity exec --fakeroot --bind "$active:/mnt" "$pristine" sh -c '
		chmod -R u+rwX /mnt
		chown -R root:root /mnt
	'
}

configure_gitlab_docker() {
	"$RUNTIME" exec gitlab update-permissions >/dev/null 2>&1 || true
	"$RUNTIME" exec gitlab sh -c "
		sed -i \"s|^external_url.*|external_url '${PUBLIC_GITLAB_URL}'|\" /etc/gitlab/gitlab.rb
		sed -i \"/^nginx\\['listen_port'\\]/d; /^nginx\\['listen_https'\\]/d\" /etc/gitlab/gitlab.rb
		printf \"%s\\n\" \"nginx['listen_port'] = ${GITLAB_PORT}\" \"nginx['listen_https'] = false\" >> /etc/gitlab/gitlab.rb
	"
	"$RUNTIME" exec gitlab gitlab-ctl reconfigure
}

configure_gitlab_singularity() {
	singularity exec "instance://$GITLAB_INSTANCE" update-permissions >/dev/null 2>&1 || true
	singularity exec "instance://$GITLAB_INSTANCE" sh -c "
		sed -i \"s|^external_url.*|external_url '${PUBLIC_GITLAB_URL}'|\" /etc/gitlab/gitlab.rb
		sed -i \"/^nginx\\['listen_port'\\]/d; /^nginx\\['listen_https'\\]/d\" /etc/gitlab/gitlab.rb
		printf \"%s\\n\" \"nginx['listen_port'] = ${GITLAB_PORT}\" \"nginx['listen_https'] = false\" >> /etc/gitlab/gitlab.rb
	"
	singularity exec "instance://$GITLAB_INSTANCE" gitlab-ctl reconfigure
}

repair_singularity_service_permissions() {
	# These official images run several internal service accounts. On a host
	# without subordinate uid/gid ranges, Singularity's single-ID fakeroot can
	# leave archived runtime files owned by its emulated root. Repair only the
	# disposable active sandboxes; the pristine images remain unchanged.
	singularity exec "instance://$REDDIT_INSTANCE" sh -c '
		chown -R postgres:postgres /usr/local/pgsql/data
		chown postgres:postgres /run/postgresql
		chmod 775 /run/postgresql
		if [ -e /run/postgresql/.s.PGSQL.5432.lock ]; then
			chown postgres:postgres /run/postgresql/.s.PGSQL.5432.lock
		fi
		supervisorctl restart postgres
	'
	singularity exec "instance://$GITLAB_INSTANCE" sh -c '
		chown -R git:git /var/opt/gitlab/gitaly /opt/gitlab/var/puma
		chmod 700 /var/opt/gitlab/gitaly /var/opt/gitlab/gitaly/run /opt/gitlab/var/puma
		gitlab-ctl restart gitaly
		gitlab-ctl restart puma
	'
}

wait_for_http() {
	local name="$1"
	local port="$2"
	local path="$3"
	local attempts="$4"
	local code
	echo "Waiting for $name to become healthy on port $port..."
	for _ in $(seq 1 "$attempts"); do
		code=$(curl --silent --output /dev/null --write-out '%{http_code}' \
			--max-time 5 "http://127.0.0.1:${port}${path}" || true)
		case "$code" in
			2*|3*) return ;;
		esac
		sleep 5
	done
	echo "$name did not return HTTP 2xx/3xx (last status ${code:-000})." >&2
	exit 5
}

start_docker_environment() {
	remove_docker_container forum
	remove_docker_container gitlab
	"$RUNTIME" run --name forum \
		-p "${REDDIT_PORT}:80" \
		-e RATELIMIT_WHITELIST="0.0.0.0/0,::/0" \
		-d "$REDDIT_IMAGE"
	"$RUNTIME" run --name gitlab \
		-p "${GITLAB_PORT}:8023" \
		-d "$GITLAB_IMAGE" \
		/opt/gitlab/embedded/bin/runsvdir-start
	configure_gitlab_docker
}

start_singularity_environment() {
	stop_singularity_instance "$REDDIT_INSTANCE"
	stop_singularity_instance "$GITLAB_INSTANCE"
	normalize_active_sandbox_for_removal "$REDDIT_SANDBOX" "$REDDIT_ACTIVE"
	normalize_active_sandbox_for_removal "$GITLAB_SANDBOX" "$GITLAB_ACTIVE"
	clone_sandbox "$REDDIT_SANDBOX" "$REDDIT_ACTIVE"
	clone_sandbox "$GITLAB_SANDBOX" "$GITLAB_ACTIVE"
	singularity instance run --fakeroot --net \
		--network-args "portmap=${REDDIT_PORT}:80/tcp" \
		--writable --env RATELIMIT_WHITELIST="0.0.0.0/0,::/0" \
		"$REDDIT_ACTIVE" "$REDDIT_INSTANCE" 9>&-
	singularity instance run --fakeroot --net \
		--network-args "portmap=${GITLAB_PORT}:8023/tcp" \
		--writable "$GITLAB_ACTIVE" "$GITLAB_INSTANCE" \
		/opt/gitlab/embedded/bin/runsvdir-start 9>&-
	for _ in $(seq 1 120); do
		if singularity exec "instance://$GITLAB_INSTANCE" \
			test -f /etc/gitlab/gitlab.rb >/dev/null 2>&1; then
			break
		fi
		sleep 5
	done
	configure_gitlab_singularity
	repair_singularity_service_permissions
}

start_environment() {
	prepare_environment
	if [ "$RUNTIME" = docker ]; then
		start_docker_environment
	else
		start_singularity_environment
	fi
	wait_for_http GitLab "$GITLAB_PORT" /explore 180
	wait_for_http Reddit "$REDDIT_PORT" / 120
	echo "WASP environments started with $RUNTIME."
}

stop_environment() {
	if [ "$RUNTIME" = docker ]; then
		remove_docker_container forum
		remove_docker_container gitlab
	else
		stop_singularity_instance "$REDDIT_INSTANCE"
		stop_singularity_instance "$GITLAB_INSTANCE"
	fi
}

status_environment() {
	echo "runtime=$RUNTIME"
	if [ "$RUNTIME" = docker ]; then
		"$RUNTIME" ps -a --filter name=gitlab --filter name=forum
	else
		singularity instance list
	fi
	for service in "gitlab:${GITLAB_PORT}" "reddit:${REDDIT_PORT}"; do
		name="${service%%:*}"
		port="${service##*:}"
		code=$(curl --silent --output /dev/null --write-out '%{http_code}' \
			--max-time 5 "http://127.0.0.1:${port}/" || true)
		echo "$name HTTP ${code:-000}"
	done
}

case "$COMMAND" in
	download)
		download_archives
		;;
	prepare)
		prepare_environment
		;;
	start|reset)
		start_environment
		;;
	stop)
		stop_environment
		;;
	status)
		status_environment
		;;
	*)
		echo "Usage: $0 {download|prepare|start|reset|stop|status}" >&2
		exit 2
		;;
esac
