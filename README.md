### INTRO ###

This script aims to resolve the problem around the pre-1.16 dragonfly installations
where when in cluster_mode, and one of the nodes restart, its id changes, hence
the cluster breaks, and each node needs to be reconfigured with `DFLYCLUSTER CONFIG` command.

However since **1.16** there has been introduced a 
[persistent cluster_id](https://github.com/dragonflydb/dragonfly/pull/2695)
feature, hence making this script theoretically **obsolete**! 

This intends to be a cloned p2p script to be run automatically on every 
cluster node when the dragonfly service restarts on that node. It facilitates
systemd's path monitoring to detect modification of dragon's pid file

The script assumes that all nodes share the SAME configuration, which is
stored in `/etc/dragonfly/cluster.conf`. So it updates that conf with the new local
cluster node id, and then connects to the other peers and uses
1. The conf we already have in memory with the new local id
2. The node ids for the rest nodes that the remote node we are
currently connected to has, to further update the conf in memory
and then applys that conf to the peer's dragon.

Remember that this script should be identically cloned to all cluster nodes
and it will run on every node.

It assumes cluster has been already configured at least once manually with the
DFLYCLUSTER CONFIG '[{...}]'


### INSTALL ###

1. Fill in the IPs in `cluster.conf` and modify accordingly if not 4 nodes.
The ids will be auto discovered by the script 

2. Modify `.env` if needed

3. Run `setup.py` with root privileges


### Notes ###

1. tested with the following version: 

`dragonfly v1.14.3-ea6b0ca6772e05c251546ec873bf46ef97d5c588 
build time: 2024-02-06 19:34:29`


2. Configures `/etc/dragonfly/dragonfly.conf` with
```
--admin_port=<PORT>
--cluster_mode=yes
```

The PORT should be exposed to the cluster's network.


3. Installs paramiko and `redis-cli`, `paramiko` and `systemd-python`

4. The conf is kept under `/etc/dragonfly/cluster.conf`. Its used by the script in case the 
"CLUSTER NODES" commands fails (the case is the node been restarted and no other node has updated 
its conf yet). The script overwrites the cluster.conf after every successful dragonfly reconfiguration.

Every time a dragonfly node is restarted, the script `reconf_dragon_online.py` is automatically run. 
It connects to every other node and updates its configuration. There is race condition avoidance 
mechanism via a lock file under `/tmp/reconf_dragon_online.lock` in case another peer is also
connected to the same node at that time.


5. Mandatory Files needed for the automatic reconfiguration and propagation of cluster node ids, 
each time dragonfly server restarts at any node:

- `reconf_dragon_online.py` in the right location that service file points to.
- The 3 systemd files for 'systemd':
-- /etc/systemd/system/dragonfly.service   (auto created by the installation)
-- /etc/systemd/system/reconf_dragon_online.py
-- /etc/systemd/system/reconf_dragon_online.path
- /etc/dragonfly/cluster.conf
