def dijkstra(graph,src):
    if graph == None:
        return None
    length = len(graph)
    type_ = type(graph)

    if type_ == list:
        nodes = [i for i in xrange(length)]
    elif type_ == dict:
        nodes = graph.keys()

    visited = [src]
    path = {src:{src:[]}}
    if src not in nodes:
        return None
    else:
        nodes.remove(src)
    distance_graph = {src:0}
    pre = next = src
    while nodes:
        distance = float('inf')
        for v in visited:
             for d in nodes:
                new_dist = graph[src][v] + graph[v][d]
                if new_dist < distance:
                    distance = new_dist
                    next = d
                    pre = v
                    graph[src][d] = new_dist

        path[src][next] = [i for i in path[src][pre]]
        path[src][next].append(next)
        distance_graph[next] = distance
        visited.append(next)
        nodes.remove(next)

    return distance_graph, path


if __name__ == '__main__':
    graph_list = [   [0, 2, 1, 4, 5, 1],
            [1, 0, 4, 2, 3, 4],
            [2, 1, 0, 1, 2, 4],
            [3, 5, 2, 0, 3, 3],
            [2, 4, 3, 4, 0, 1],
            [3, 4, 7, 3, 1, 0]]

    graph_dict = {  "s1":{"s1": 0, "s2": 2, "s10": 1, "s12": 4, "s5":3},
                    "s2":{"s1": 1, "s2": 0, "s10": 4, "s12": 2, "s5":2},
                    "s10":{"s1": 2, "s2": 1, "s10": 0, "s12":1, "s5":4},
                    "s12":{"s1": 3, "s2": 5, "s10": 2, "s12":0,"s5":1},
                    "s5":{"s1": 3, "s2": 5, "s10": 2, "s12":4,"s5":0},
    }

    distance, path = dijkstra(graph_list, 2)
    #print distance, '\n', path
    distance, path = dijkstra(graph_dict, 's1')
    print distance, '\n', path
