#! /usr/bin/env python3

"""
This is a clone p2p script to be run automatically on every cluster node
when the dragonfly service restarts on that node. In that case a new
cluster node id is given to the node (no persistent node ids yet) which
means we need to reconfigure the cluster with DFLYCLUSTER CONFIG command.
The script assumes that all nodes share the SAME configuration, which is
stored in /etc/dragonfly/cluster.conf, but the path can be overriden by a
positional arg to this script. So it updates that conf with the new local
cluster node id, and then connects to the other peers and uses
1. The conf we already have in memory with the new local id
2. The node ids for the rest nodes that the remote node we are
currently connected to has, to further update the conf in memory
and then applys that conf to the peer's dragon.

Remember that this script should be identically cloned to all cluster nodes
and it will run on every node.

It assumes cluster has been already configured at least once manually with the
DFLYCLUSTER CONFIG '[{...}]'
"""
import copy
import json
import logging
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import paramiko
import redis
from systemd.journal import JournalHandler
from decouple import config

# Global static values
DEBUG = False  # Print to stdout/stderr?
LOGLEVEL = logging.INFO   # or INFO, WARNING

# parse .env
SSH_KEY_PATH = config("SSH_KEY_PATH")
USER = config("SSH_USER")
REDIS_ADM_PORT = config("REDIS_ADM_PORT")
CLUSTER_CONF_PATH = config("CLUSTER_CONF_FILE")

# no need to adjust
LOCK_FILE = '/tmp/reconf_dragon_online.lock'
LOCK_TIMEOUT = 12  # sec

# global var
logger: logging.Logger | None = None  # set in main()


@contextmanager
def _connect_ssh(host: str, ssh_key_path: str = SSH_KEY_PATH) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        private_key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
        # this is executed inside each thread, hence w8 (timeout set) shouldn't be an issue
        # it is needed in case of simultaneous reboots in which case a peer may be slow to start
        client.connect(hostname=host, username=USER, pkey=private_key, port=22,
                       timeout=10, banner_timeout=15)
    except Exception as e:
        logger.error(f"Failed connecting via ssh to {host}:\nEXC: {e}")
        client = None
    finally:
        # Another try blk, to ensure the close() is called if an exception occured in the caller
        try:
            yield client
        finally:
            if client is not None:
                client.close()


def send_command(command, client=None, host="localhost", port=REDIS_ADM_PORT, print_errors=True) -> str:
    """
    Send a redis command to dragon server
    If client is specified, host and port are not used at all
    """
    result = ""

    cmd = command.split() if isinstance(command, str) else command
    for i in range(0, 5):
        try:
            redis_cli = client or redis.Redis(decode_responses=True, host=host, port=port, db=0)
            result = redis_cli.execute_command(*cmd)  # needs command as *args
            redis_cli.close()

            return result
        except redis.exceptions.ConnectionError as e:
            if print_errors and i == 4:
                logger.error(f"Error: Failed to connect to {host}:{port}, exc: {e}")
        except UnicodeDecodeError as e:
            if print_errors and i == 4:
                logger.error(f'Error: Dragon returned trash: {e}')
                break
        except Exception as e:
            if print_errors and i == 4:
                if 'is not yet configured' in str(e).lower():
                    logger.warning("Cluster is not yet configured")
                else:
                    logger.error(f'Error: Unexpected exception from redis cli: {e}')
        time.sleep(0.1 * i)

    if print_errors:
        logger.error(f"Unable to run command {cmd} against {host}:{port}, tried 5 attempts!")

    return result


def exit_w_error(error: str | Exception, exit_code=1):
    logger.critical(f"EXITING with ERROR: {str(error)}")
    sys.exit(exit_code)


def update_config_data(data: list[dict], nodes: dict):
    """
    update data taken from cluster.conf
    with ids currently in use by dragon
    """
    for node_ip, node_id in nodes.items():
        if len(node_id) > 10:
            # in current versions node ids are 40 chars but may change?
            for host in data:
                if host["master"]["ip"] == node_ip:
                    host["master"]["id"] = node_id


def dynamic_get_nodes_info(from_host: str) -> dict:
    nodes = {}

    res = send_command(["CLUSTER", "NODES"], host=from_host)
    for line in res.split('\r\n'):
        l = line.strip(" \n")
        if l and 'master' in l:
            node_id = l.split()[0]
            node_ip = l.split()[1].split(':')[0]
            nodes[node_ip] = node_id

    return nodes


def apply_config_local(encoded_data: str):
    # Run the DFLYCLUSTER CONFIG command
    result = send_command(
        ["DFLYCLUSTER", "CONFIG", f"{encoded_data}"], host="localhost")
    if not result:
        exit_w_error('applying the config locally')


def apply_peer_conf(host: str, encoded_data: str) -> bool:
    res = send_command(["DFLYCLUSTER", "CONFIG", f"{encoded_data}"], host=host)
    if res == "OK":
        logger.info(f"Successfully updated {host}")
        return True
    else:
        logger.error(f"Failed to Config update on {host} Returned: {res}")
        return False


def acquire_lock(ssh_c: paramiko.SSHClient):
    seconds = 0

    while True:
        # Try to create the lock file
        stdin, stdout, stderr = ssh_c.exec_command(
            f"if [ ! -f {LOCK_FILE} ]; then touch {LOCK_FILE}; echo 'Lock acquired'; else echo 'Locked'; fi")
        output = stdout.read().decode().strip()
        if output == 'Lock acquired':
            # logger.debug('Lock acquired')
            break
        else:
            if seconds == 0:
                logger.debug('Waiting for the lock')
            time.sleep(1)
            seconds += 1

        # Check for LOCK_TIMEOUT
        if seconds > LOCK_TIMEOUT:
            logger.error('Lock acquisition timed out')
            break


def _read_remote_conf_file(ssh_c, path=CLUSTER_CONF_PATH):
    conf = []

    # Open an SFTP session
    sftp = ssh_c.open_sftp()
    try:
        # Open the file
        with sftp.file(path, 'r') as f:
            # Read the file
            file_content = f.read()
        # Load the file content as JSON
        conf = json.loads(file_content)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to parse JSON from file {path}: {e}")
    finally:
        # Close the SFTP session
        sftp.close()

    return conf


def update_peer(host: str, local_ip: str, local_id: str, data_copy: list[dict]) -> bool:
    """
    Connect to each host and update the cluster configuration
    First get the peer's knowledge of IDs, not the local,
    because it might have already been changed by another peer,
    update the configuration string with that knowledge except the
    local_id which the current node knows better since it is its own id
    """
    is_success = False

    with _connect_ssh(host) as ssh_c:
        if ssh_c:
            logger.info(f"Connected to {host}")

            try:
                acquire_lock(ssh_c)

                # First read the cluster.conf file, it has priority over initiator's conf
                data = _read_remote_conf_file(ssh_c)
                if not data:
                    logger.error(
                        f"Failed to load configuration from {host}. "
                        f"Continuing with initiator's info conf")
                    data = data_copy

                # get the current cluster info with 'cluster nodes' sometimes empty
                # but if not empty then it means it is the updated values
                nodes = dynamic_get_nodes_info(host)

                # However, the initiator knows their local_id better
                nodes[local_ip] = local_id

                # update the data read from file with the dynamic info (if any)
                # and the local_id passed by the initiator (100% correct)
                update_config_data(data, nodes)

                encoded_str = json.dumps(data)

                # Insert the new config into the local cluster conf
                is_success = apply_peer_conf(host, encoded_str)

                # write the cluster.conf file, lock has been released
                if is_success:
                    logger.debug(f"writing the config to {host}")

                    # Prettify the JSON data
                    pretty_json = json.dumps(data, indent=4)

                    # Create an SFTP client
                    sftp = ssh_c.open_sftp()

                    # Open a remote file to write the JSON data
                    with sftp.file('/tmp/abcdef_cluster.conf', 'w') as f:
                        f.write(pretty_json)
                    # move it via sudo in case the dest wasn't writable
                    ssh_c.exec_command("sudo mv /tmp/abcdef_cluster.conf /etc/dragonfly/cluster.conf")

                    # Close the SFTP client
                    sftp.close()
                    logger.debug(f"finished writing the config to {host}")
                else:
                    # already logged failure inside apply_peer_conf()
                    logger.warning(f"As a result cluster.conf on {host} is left updated")

            finally:
                # Remove the lock file
                ssh_c.exec_command(f"rm -f {LOCK_FILE}")
                logger.debug('Lock released')

    return is_success


def connect_to_peers(peers: list[str], data: list[dict], local_ip: str, local_id: str):
    """Connect to all peers in parallel to update conf with local_id"""
    # with new_redis_cluster(peers) as cluster_cli:
    threads = []
    for host in peers:
        # pass the initiator's data to each peer in case their conf has been ruined
        data_copy = copy.deepcopy(data)

        thread = threading.Thread(
            target=update_peer,
            args=(host, local_ip, local_id, data_copy))
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()


def _grep_ip(an_ip):
    try:
        output = subprocess.check_output(f"ip a | grep {an_ip}", shell=True)
        if output:
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False


def get_local_id() -> str:
    local_id = send_command(['DFLYCLUSTER', 'MYID'], host="localhost")
    if not local_id:
        exit_w_error('Error getting the local cluster node id')

    return local_id


def get_local_ip(data: list[dict]) -> str:
    """ find out the IP of the current host from the existing static configuration """
    conf_ips = [node["master"]["ip"] for node in data]

    # First look for the already defined ips in CLUSTER_CONF
    for ip in conf_ips:
        if _grep_ip(ip):
            return ip

    # should never reach here
    exit_w_error("Error: Could not find any ip in conf assigned to any interface")


def get_peers(data: list[dict], local_ip: str) -> list[str]:
    conf_ips = [node["master"]["ip"] for node in data]
    conf_ips.remove(local_ip)

    return conf_ips


def setup_logger():
    global logger

    # logging.basicConfig(format='[%(levelname)s] %(asctime)s %(message)s', level=logging.DEBUG)
    logger = logging.getLogger("reconf_dragon_online")

    # instantiate the JournaldLogHandler to hook into systemd
    journald_handler = JournalHandler()

    # set a formatter to include the level name
    journald_handler.setFormatter(logging.Formatter(
        '[%(levelname)s] %(asctime)s %(message)s (line: %(lineno)d)'
    ))

    # add the journald handler to the current logger
    logger.addHandler(journald_handler)

    # add stdout handler only when DEBUG is True
    if DEBUG:
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(logging.Formatter(
            '[%(levelname)s] %(asctime)s %(message)s (line: %(lineno)d)'
        ))
        logger.addHandler(stdout_handler)

    logger.setLevel(LOGLEVEL)

    # now can be used like:
    # logger.info('example service starting')
    # logger.error('example service error')


def wait_for_dragonfly(host="localhost", admin_port=REDIS_ADM_PORT):
    while True:
        try:
            with socket.create_connection((host, admin_port), timeout=1) as conn:
                # Send INFO command
                conn.sendall(b'*1\r\n$4\r\nINFO\r\n')

                # Read response
                response = conn.recv(4096)

                # Check if correct response
                response = response.decode(encoding='utf-8').lower()
                if 'server' in response and 'redis_version' in response:
                    break
        except OSError:
            time.sleep(1)


def wait_for_ssh(host, port=22, interval=10):
    seconds = 0
    while seconds < 30:
        try:
            sock = socket.create_connection((host, port), interval)
            sock.close()
            return
        except socket.error:
            logger.warning(
                f"SSH server not reachable at {host}:{port}. Retrying in {interval} seconds...")
            time.sleep(interval)
            seconds += interval

    logger.critical("{host} SSH server not reachable after 30 seconds!")


def main():
    setup_logger()

    # wait for dragonfly service to complete restart. This shouldn't be needed but
    # systemd's trigger and binds are not totally startworthy for "oneshot" services (aka scripts).
    # time.sleep(2)
    wait_for_dragonfly()

    # Use the already configured system's cluster.conf
    try:
        with Path(CLUSTER_CONF_PATH).expanduser().absolute().open() as fin:
            data = json.load(fin)
    except Exception:  # noqa
        exit_w_error(f"Failed to parse {CLUSTER_CONF_PATH}")

    # find out which local IP should be used by dragon
    local_ip = get_local_ip(data)

    # get the other IPs, subtracting local_ip from the conf string
    peers = get_peers(data, local_ip)
    # assert len(peers) == 3
    for p in peers:
        wait_for_ssh(p)

    # query local dragon via redis cli for the local id
    local_id = get_local_id()

    # dragon's server data are more trustworthy than the cluster.conf file
    # unless the cluster is not configured yet, in which case we get empty dict
    nodes = dynamic_get_nodes_info("localhost")  # nodes = {} if not yet configured
    nodes[local_ip] = local_id

    # connect to each machine and get the new ID
    update_config_data(data, nodes)

    # ### LOCAL ACT ### #
    # Encode the content to a json str
    encoded_data = json.dumps(data)
    pretty_encoded_data = json.dumps(data, indent=4)

    # apply the configuration in this node via redis cli
    apply_config_local(encoded_data)

    # write the local cluster.conf for reference
    with open(CLUSTER_CONF_PATH, 'w') as fout:
        fout.write(pretty_encoded_data)

    # ### REMOTE (PEERS) ACT ### #
    # connect to other nodes to send the local id, maintaining the other ids
    connect_to_peers(peers, data, local_ip, local_id)


if __name__ == "__main__":
    main()
