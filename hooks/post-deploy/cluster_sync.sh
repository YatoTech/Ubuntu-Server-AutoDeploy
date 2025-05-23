#!/usr/bin/env bash
# hooks/post-deploy/cluster_sync.sh

sync_cluster() {
  local nodes=($(get_cluster_nodes))
  
  parallel-ssh -i -H "${nodes[*]}" <<EOF
sudo atomic-deploy/updater.sh \
  --version ${DEPLOY_VERSION} \
  --config ${CONFIG_HASH}
EOF
}