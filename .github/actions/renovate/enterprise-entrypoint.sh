#!/bin/bash

apt update

apt install -y gettext docker-buildx

# Check if PS1 is unset; using ${PS1:-} to avoid "unbound variable" error
# in non-interactive shells.
# shellcheck disable=SC2016
sed -i '7s/\[ -z "$PS1" \]/[ -z "${PS1:-}" ]/' /etc/bash.bashrc

ls -lah /var/run/docker.sock

# Add the group of /var/run/docker.sock to ubuntu user
GROUP_ID=$(stat -c '%g' /var/run/docker.sock)
GROUP_NAME=$(getent group "$GROUP_ID" | cut -d: -f1)

if [ -z "$GROUP_NAME" ]; then
  GROUP_NAME="docker_group"
  groupadd -g "$GROUP_ID" "$GROUP_NAME"
fi

usermod -aG "$GROUP_NAME" ubuntu

chown -R ubuntu:ubuntu /tmp

# Serve wolfi-packages files as an API because renovate can't access files outside repository dir
python3 -m http.server 8000 --directory /tmp/renovate/wolfi-packages &

runuser -u ubuntu -w RENOVATE_CONFIG_FILE,RENOVATE_TOKEN,RH_REGISTRY_USERNAME,RH_REGISTRY_PASSWORD,ARTIFACTORY_USERNAME,ARTIFACTORY_PASSWORD renovate
