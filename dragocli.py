# a very simple python client to test that the dragon cluster works

import random
import string

from redis import RedisCluster
from redis.cluster import ClusterNode


# Create ClusterNode objects for your nodes
node_A = ClusterNode('{ip1}', 6379)
node_B = ClusterNode('{ip2}', 6379)
node_C = ClusterNode('{ip3}', 6379)
node_D = ClusterNode('{ip4}', 6379)

# Provide the node objects of your cluster
startup_nodes = [node_A, node_B, node_C, node_D]

# Create a Redis cluster object
rc = RedisCluster(startup_nodes=startup_nodes, decode_responses=True)

# write 10 random values to check sharding works
for i in range(10):
    a = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(3))
    b = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))

    # Set a key-value pair
    rc.set(a, b)
    print(rc.get(a))

