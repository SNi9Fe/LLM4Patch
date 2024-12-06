import json
import os

class Node:
    def __init__(self, id, type, url):
        self.id = id
        self.type = type
        self.url = url
        self.score = 0


class Edge:
    def __init__(self, type, from_, to, next=None):
        self.type = type
        self.from_ = from_
        self.to = to
        self.next = next


class Graph:
    def __init__(self):
        self.nodes: Node = []
        self.edges: Edge = []
        # 邻接表头
        self.head = []
        # 边数
        self.edge_cnt = 0
        # 点数
        self.node_cnt = 0
        # 遍历的时候是否访问过
        self.vis = []

    def add_node(self, type, url):
        print(self.node_cnt, type, url)
        self.nodes.append(Node(self.node_cnt, type, url))
        self.head.append(None)
        self.vis.append(False)
        self.node_cnt += 1

    def add_edge(self, type, node1_id, node2_id):
        print(self.edge_cnt, type, node1_id, node2_id)
        # check if the edge is already exist
        for edge in self.edges:
            if (edge.from_ == node1_id and edge.to == node2_id) or (edge.from_ == node2_id and edge.to == node1_id):
                return
        self.edges.append(Edge(type, node1_id, node2_id))
        self.edges[self.edge_cnt].next = self.head[node1_id]
        self.head[node1_id] = self.edge_cnt
        self.edge_cnt += 1

    def dfs(self, now, father):
        if self.vis[now]:
            return
        self.vis[now] = True
        # print(self.nodes[now].id, father, self.head[now], self.nodes[now].type, self.nodes[now].url)
        edge_id = self.head[now]
        while edge_id != None:
            to = self.edges[edge_id].to
            self.dfs(to, now)
            edge_id = self.edges[edge_id].next
            
    def save(self):
        data = {
            "nodes": [node.__dict__ for node in self.nodes],
            "edges": [edge.__dict__ for edge in self.edges]
        }
        os.makedirs("Graph_tmp", exist_ok=True)
        file_name = f"Graph_tmp/{self.nodes[0].url}.json"
        with open(file_name, "w") as f:
            json.dump(data, f, indent=4)


if __name__ == "__main__":
    graph = Graph()
    graph.add_node("root", "http://root.com")
    graph.add_node("NVD", "http://nvd.com")
    graph.add_node("red hat", "http://redhat.com")
    graph.add_node("debian", "http://debian.com")
    graph.add_node("github", "http://github.com")
    graph.add_edge("contain", 0, 1)
    graph.add_edge("contain", 0, 2)
    graph.add_edge("contain", 0, 3)
    graph.add_edge("contain", 0, 4)
    graph.add_node("hybird", "http://test1.com")
    graph.add_node("hybird", "http://test2.com")
    graph.add_node("hybird", "http://test3.com")
    graph.add_node("hybird", "http://test4.com")
    graph.add_edge("contasin", 1, 5)
    graph.add_edge("contasin", 1, 8)
    graph.add_edge("contasin", 5, 6)
    graph.add_edge("contasin", 2, 5)
    graph.add_edge("contasin", 2, 8)
    graph.add_edge("contasin", 2, 7)
    graph.add_edge("contasin", 3, 7)
    graph.dfs(0)
