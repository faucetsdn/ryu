def floyd(graph):
    length = len(graph)
    path = {}

    for i in xrange(length):
        path.setdefault(i, {})
        for j in xrange(length):
            if i == j:
                continue

            path[i].setdefault(j, [i,j])
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
            path[src].setdefault(dst, [src,dst])
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


if __name__ == '__main__':
    ini = float('inf')
    graph_list = [   [0, 2, 1, 4, 5, 1],
            [1, 0, 4, 2, 3, 4],
            [2, 1, 0, 1, 2, 4],
            [3, 5, 2, 0, 3, 3],
            [2, 4, 3, 4, 0, 1],
            [3, 4, 7, 3, 1, 0]]

    graph_dict = {  "s1":{"s1": 0, "s2": 2, "s10": 1, "s12": 4},
                    "s2":{"s1": 1, "s2": 0, "s10": 4, "s12": 2},
                    "s10":{"s1": 2, "s2": 1, "s10": 0, "s12":1},
                    "s12":{"s1": 3, "s2": 5, "s10": 2, "s12":0},
    }

    #new_graph, path= floyd_dict(graph_dict)    
    new_graph, path = floyd(graph_list)
    print new_graph, '\n\n\n', path
