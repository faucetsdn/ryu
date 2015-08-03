"""
This file define the routing algorithms,
including Dijkstra, Floyd, Prim and Kruskal.
Author:www.muzixing.com

Date                Work
2015/8/3            new
2015/8/3            done
"""


def floyd(graph):
    length = len(graph)
    path = {}

    for i in xrange(length):
        path.setdefault(i, {})
        for j in xrange(length):
            if i == j:
                continue

            path[i].setdefault(j, [i, j])
            new_node = None

            for k in xrange(length):
                if k == j:
                    continue

                new_len = graph[i][k] + graph[k][j]
                if graph[i][j] > new_len:
                    graph[i][j] = new_len
                    new_node = k
            if new_node:
                path[i][j].insert(-1, new_node)

    return graph, path


def floyd_dict(graph):
    length = len(graph)
    path = {}

    for src in graph:
        path.setdefault(src, {})
        for dst in graph[src]:
            if src == dst:
                continue
            path[src].setdefault(dst, [src, dst])
            new_node = None

            for mid in graph:
                if mid == dst:
                    continue

                new_len = graph[src][mid] + graph[mid][dst]
                if graph[src][dst] > new_len:
                    graph[src][dst] = new_len
                    new_node = mid
            if new_node:
                path[src][dst].insert(-1, new_node)

    return graph, path


def dijkstra(graph, src):
    if graph is None:
        print "Graph is empty."
        return None
    length = len(graph)
    type_ = type(graph)

    # Initiation
    if type_ == list:
        nodes = [i for i in xrange(length)]
    elif type_ == dict:
        nodes = graph.keys()
    visited = [src]
    path = {src: {src: []}}
    if src not in nodes:
        print "Src is not in nodes."
        return None
    else:
        nodes.remove(src)
    distance_graph = {src: 0}
    pre = next = src
    no_link_value = 100000

    while nodes:
        distance = no_link_value
        for v in visited:
            for d in nodes:
                new_dist = graph[src][v] + graph[v][d]
                if new_dist <= distance:
                    distance = new_dist
                    next = d
                    pre = v
                    graph[src][d] = new_dist

        if distance < no_link_value:
            path[src][next] = [i for i in path[src][pre]]
            path[src][next].append(next)
            distance_graph[next] = distance
            visited.append(next)
            nodes.remove(next)
        else:
            print "Next node is not found."
            return None

    return distance_graph, path


func = {9: floyd_dict}
        # other module method.


def get_paths(graph, flags=None):
    """
    @graph: network toplogy graph in network_aware.
    @src: dpid.
    @dst: a list of dpid.
    @flags: OXP flags.
    """

    distance_graph, path_dict = func[flags](graph)

    return distance_graph, path_dict
