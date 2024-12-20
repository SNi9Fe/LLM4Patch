import requests
import re
import graph
from urllib.parse import urlparse
import pyecharts.options as opts
from pyecharts.charts import Graph as PyGraph
from get_advisory import get_nvd_advisory, get_modified_files, get_redhat_advisory
from utils import get_links, remove_anchor_from_url
import json


class Tracer:
    def __init__(self, cve_id):
        self.reference_network = graph.Graph()
        self.cve_id = cve_id

    # Remove the trailing path of the issue node URL.
    def remove_trail_from_url(self, url):
        url_parts = url.split("/")
        if url_parts[-1] in ["checks", "commits", "files"]:
            processed_url = "/".join(url_parts[:-1])
        elif url_parts[-2] in ["checks", "commits", "files"]:
            processed_url = "/".join(url_parts[:-2])
        else:
            processed_url = url
        return processed_url

    def extract_urls_from_debian_list(self):
        urls = []
        with open("./debian/list", "r") as file:
            lines = file.readlines()
            # 转换为迭代器对象
            lines_iter = iter(lines)

        for line in lines_iter:
            if self.cve_id in line:
                line = next(lines_iter)
                while "CVE" not in line:
                    if "NOTE:" in line and "https:" in line:
                        pattern = r"(https?://\S+)"
                        match = re.search(pattern, line)
                        if match:
                            # print(match.group(0))
                            url = match.group(0)
                            url = remove_anchor_from_url(url)
                            urls.append(url)

                    line = next(lines_iter)
                break

        return urls

    def extract_urls_from_redhat(self, Json):

        urls = []
        try:
            bug_id = Json["bugs"]
        except (KeyError, TypeError) as e:
            return []

        for bug_id in Json["bugs"]:
            for comment in Json["bugs"][bug_id]["comments"]:
                # print(comment["text"])
                pattern = r"(https?://\S+)"
                for url in re.findall(pattern, comment["text"]):
                    url = remove_anchor_from_url(url)
                    urls.append(url)

        return urls

    def request_and_parse_advisories(self):
        # Request and parse advisories from NVD, Debian, and Red Hat
        nvd_advisory = get_nvd_advisory(self.cve_id)
        debian_advisory = ""
        redhat_advisory = get_redhat_advisory(self.cve_id)

        # Extract URL references from each advisory and add them as child nodes
        self.extract_and_add_url_references("NVD", nvd_advisory)
        self.extract_and_add_url_references("Debian", debian_advisory)
        self.extract_and_add_url_references("Red Hat", redhat_advisory)

    def initialize_reference_network(self):
        # Initialize the reference network with the CVE as the root node
        self.reference_network.add_node("root", self.cve_id)

        # Add advisory source nodes as child nodes of the root node
        self.reference_network.add_node("NVD", "http://nvd.com")
        self.reference_network.add_node("debian", "http://debian.com")
        self.reference_network.add_node("redhat", "http://redhat.com")
        self.reference_network.add_node("github", "http://github.com")
        self.reference_network.add_edge("", 0, 1)
        self.reference_network.add_edge("", 0, 2)
        self.reference_network.add_edge("", 0, 3)
        self.reference_network.add_edge("", 0, 4)

    def classify_reference_nodes(self, url):
        # Classify reference nodes into patch nodes, issue nodes, and hybrid nodes
        # return a tuple ("type",url)
        if self.is_patch_node(url):
            if self.is_useless_patch(url):
                return "useless", url
            return "patch", url
        elif self.is_issue_node(url):
            return "issue", self.is_issue_node(url)
        else:
            return "hybrid", url

    def check_repeat_patch(self, url1, url2):
        netloc1 = urlparse(url1).netloc
        netloc2 = urlparse(url2).netloc
        commit_sha_regex = re.compile(
            r"(?:/commit/|;h=|[?&]h=)([a-fA-F0-9]{7,40})"
        )
        match1 = commit_sha_regex.search(url1)
        match2 = commit_sha_regex.search(url2)
        if match1 and match2:
            sha1 = match1.group(1)
            sha2 = match2.group(1)
            if netloc1 == netloc2 and sha1 == sha2:
                return True
        return False

    def add_node_and_edge(self, url, now, strict=False, edge_type="reference"):
        type, url = self.classify_reference_nodes(url)
        # check if the type is hybrid or useless
        if (strict and type == "hybrid") or type == "useless":
            return
        # check if the node already exists
        new_node_id = -1
        for node in self.reference_network.nodes:
            if url == node.url or (
                type == "patch" and node.type == "patch" and self.check_repeat_patch(url, node.url)
            ):
                new_node_id = node.id
                break
        # if the node does not exist, add it
        if new_node_id == -1:
            # check if the node is issue and if from github the repo is the same
            url_now_parse = urlparse(self.reference_network.nodes[now].url)
            url_parse = urlparse(url)
            if (
                self.reference_network.nodes[now].type == "issue"
                and url_now_parse.netloc == "github.com"
                and url_parse.netloc == "github.com"
            ):
                if url_now_parse.path.split("/")[1] == url_parse.path.split("/")[1]:
                    self.reference_network.add_node(type, url)
                    new_node_id = self.reference_network.node_cnt - 1
            else:
                self.reference_network.add_node(type, url)
                new_node_id = self.reference_network.node_cnt - 1
        # add edge
        if new_node_id != -1 and new_node_id != now:
            self.reference_network.add_edge(edge_type, now, new_node_id)

    def extract_and_add_url_references(self, source_node, advisory):
        # Extract URL references from the advisory and add them as child nodes
        url_references = []

        if source_node == "NVD":
            url_references = advisory["vulnerabilities"][0]["cve"]["references"]
            for reference in url_references:
                self.add_node_and_edge(remove_anchor_from_url(reference["url"]), 1)

        elif source_node == "Debian":
            url_references = self.extract_urls_from_debian_list()
            for url in url_references:
                self.add_node_and_edge(remove_anchor_from_url(url), 2)

        elif source_node == "Red Hat":
            url_references = self.extract_urls_from_redhat(advisory)
            for url in url_references:
                self.add_node_and_edge(remove_anchor_from_url(url), 3)

        # Add URL references as child nodes of the corresponding advisory source node
        # for url in url_references:
        #     self.reference_network[self.cve_id]['children'].append({'type': 'reference', 'source': source_node, 'url': url})

    def is_patch_node(self, url):
        # Check if the reference node is a patch node
        url_pattern = r"(?:https?:\/\/|ssh:\/\/|git@)[\w.-]+(?:\/|:)[\w./-]+(?:\.git)?(?:\/commit\/[a-f0-9]{7,40}|\/revision\/\d+)"
        return (
            re.match(url_pattern, url)
        )

    def is_issue_node(self, url):
        # Check if the reference node is an issue node
        github_issue_pattern = r"https://github\.com/[\w-]+/[\w-]+/issues/\d+"
        gitlab_issue_pattern = r"https://gitlab\.com/[\w-]+/[\w-]+/-/issues/\d+"
        github_PR_pattern = r"https://github\.com/[\w-]+/[\w-]+/pull/\d+"
        issue_keywords = ["bugzilla", "jira", "issues", "bugs", "tickets", "tracker"]
        issue_identifier_pattern = r"^(?:[0-9a-fA-F]+|\d+|CVE-\d{4}-\d{4,}|[A-Z]+-\d+)$"
        url_splits = url.split("/")
        if (
            re.match(github_issue_pattern, url)
            or re.match(gitlab_issue_pattern, url)
            or re.match(github_PR_pattern, url)
            or (
                any(keyword in url for keyword in issue_keywords)
                and re.match(issue_identifier_pattern, url_splits[-1])
            )
        ):
            url = remove_anchor_from_url(url)
            url = self.remove_trail_from_url(url)
            return url
        return None

    def is_useless_patch(self, patch_URL):
        modified_files_list = get_modified_files(patch_URL)
        if modified_files_list == [-1]:
            return True
        if modified_files_list == []:
            return False
        # whether folder
        non_tests_file_number = 0
        for file_path in modified_files_list:
            # 提取文件名中第一个文件夹的名称
            folder_name = file_path.split("/")[0]
            file_name = file_path.split("/")[-1]
            # 判断第一个文件夹名称是否为 "tests"以及文件名是否含有"test"，如果不是，计数器加1
            if folder_name != "tests" and re.search(r"test", file_name) == None:
                non_tests_file_number += 1

        if non_tests_file_number == 0:
            return True

        non_source_code_suffix_list = ["md", "txt", "xls", "csv", "json", "yml"]

        # count the number of source code file
        source_code_number = 0
        for file_name in modified_files_list:
            # 提取文件后缀
            file_extension = file_name.split(".")[-1]

            # 判断文件后缀是否在指定列表中
            if file_extension not in non_source_code_suffix_list:
                source_code_number += 1

        if source_code_number == 0:
            return True

        return False

    def reference_analysis(self, father, now, dep):
        # print("dep:",dep)
        # 访问过的节点不再访问
        if self.reference_network.vis[now]:
            return
        # 深度不超过5
        if dep > 3:
            return
        type = self.reference_network.nodes[now].type
        self.reference_network.vis[now] = True
        if type == "hybrid" or type == "issue":
            # print("get links: ", self.reference_network.nodes[now].url)
            links = get_links(self.reference_network.nodes[now].url)
            for link in links:
                self.add_node_and_edge(link, now, True)
        edge_id = self.reference_network.head[now]
        while edge_id != None:
            to = self.reference_network.edges[edge_id].to
            self.reference_analysis(now, to, dep + 1)
            edge_id = self.reference_network.edges[edge_id].next

    def identifier_extraction(self):
        identifiers = []
        for node in self.reference_network.nodes:
            if node.type in ["issue", "hybrid"]:
                url = node.url
            issue_identifier_pattern = r"SECURITY-\d+"
            match = re.search(issue_identifier_pattern, url)
            if match:
                identifiers.append(match.group(0))
        return identifiers

    def check_cpe(self, url):
        # vulnerabilities->cve->configurations->nodes->cpe_match->criteria
        cve_data = get_nvd_advisory(self.cve_id)
        configs = cve_data['vulnerabilities'][0]['cve']['configurations']
        for config in configs:
            cpeMatch = config['nodes'][0]['cpeMatch']
            for cpe in cpeMatch:
                github_regex = re.compile(r"https?://github\.com/([^/]+)/([^/]+)/commit/([a-fA-F0-9]{7,40})")
                match = github_regex.match(url)
                if match:
                    owner, repo, commit_sha = match.groups()
                    criteria = cpe['criteria'].split(":")
                    if criteria[2] == 'a' and (criteria[3] == owner or criteria[4] == repo):
                        return True
                
    
    def reference_augmentation(self):
        # Reference augmentation using GitHub API
        # Access token for GitHub API
        # /search/commits
        identifier_regex = re.compile(r'((?![Cc][Vv][Ee])\b(?=\w*[a-zA-Z])\w+-(?=\w*\d)\w+\b([-:](?=\w*\d)\w+)?(-(?=\w*\d)\w+)?)')

        identifiers = [self.cve_id]
        for node in self.reference_network.nodes:
            if node.type == 'issue' or node.type == 'hybrid':
                identifier = identifier_regex.search(node.url)
                if identifier:
                    identifiers.append(identifier.group(0))
        for identifier in identifiers:
            f = open("config.json")
            config = json.load(f)
            github_api_key = config["github_api_key"]
            api_url = f"https://api.github.com/search/commits?q={identifier}"
            headers = {"Authorization": f"Bearer {github_api_key}"}
            # print(api_url)
            page = 1
            while True:
                paginated_url = f"{api_url}&page={page}&per_page=30"
                try:
                    response = requests.get(paginated_url, headers=headers, timeout=10)
                    res = response.json()
                    if "items" not in res or not res["items"]:
                        break
                    res = response.json()
                    for item in res['items']:
                        if self.check_cpe(item['html_url']):
                            self.add_node_and_edge(item['html_url'], 4, True, "contain")
                except requests.exceptions.RequestException as e:
                    # print("Request Error: ", e)
                    pass
                page += 1

    def draw(self):
        categories = [
            {"name": "base"},
            {"name": "hybrid"},
            {"name": "issue"},
            {"name": "patch"},
        ]
        nodes = []
        for node in self.reference_network.nodes:
            if node.type == "hybrid":
                nodes.append(
                    {
                        "id": node.id,
                        "name": node.id,
                        "value": node.url,
                        "category": 1,
                        "symbolSize": 20,
                    }
                )
            elif node.type == "issue":
                nodes.append(
                    {
                        "id": node.id,
                        "name": node.id,
                        "value": node.url,
                        "category": 2,
                        "symbolSize": 20,
                    }
                )
            elif node.type == "patch":
                nodes.append(
                    {
                        "id": node.id,
                        "name": node.id,
                        "value": node.url,
                        "category": 3,
                        "symbolSize": 20,
                    }
                )
            else:
                nodes.append(
                    {
                        "id": node.id,
                        "name": node.id,
                        "value": node.url,
                        "category": 0,
                        "symbolSize": 20,
                    }
                )
        links = []
        for edge in self.reference_network.edges:
            links.append({"source": edge.from_, "target": edge.to})
        draw = PyGraph(
            init_opts=opts.InitOpts(width="95vw", height="95vh"),
        )
        draw.add(
            "",
            nodes,
            links,
            repulsion=8000,
            edge_label=opts.LabelOpts(is_show=True, position="middle", formatter="{b}"),
            categories=categories,
        )
        # 显示图表
        draw.render("./cve_graph_html/" + self.cve_id + ".html")

    def calc_score(self, now, dep):
        # nvd和github的直接子节点具有高置信度
        # patch到根节点路径越多，连通性越高，n表示有n条路径
        # patch到根节点路径越短，连通性越高，p表示第p条路径，dp表示路径p的长度
        # 如果路径来自nvd和github，路径长度-1
        if self.reference_network.nodes[now].type == "patch":
            self.reference_network.nodes[now].score += 1.0 / (2.0 ** (dep - 1.0))
            return
        edge_id = self.reference_network.head[now]
        while edge_id != None:
            to = self.reference_network.edges[edge_id].to
            if self.reference_network.vis[to]:
                edge_id = self.reference_network.edges[edge_id].next
                continue
            if self.reference_network.nodes[now].type == "NVD" or self.reference_network.nodes[now].type == "github":
                self.calc_score(to, dep)
            else:
                self.calc_score(to, dep + 1)
            edge_id = self.reference_network.edges[edge_id].next

    def crawl(self):
        # Entry point of the crawler
        self.initialize_reference_network()
        self.request_and_parse_advisories()
        self.reference_analysis(0, 0, 0)
        self.reference_augmentation()
        self.reference_network.save()
        self.reference_network.vis = [False] * self.reference_network.node_cnt
        self.calc_score(0, 0)
        sorted_nodes = sorted(
            self.reference_network.nodes, key=lambda node: node.score, reverse=True
        )
        score = sorted_nodes[0].score
        if score > 0:
            with open("./cve_patch.csv", "a") as file:
                for node in sorted_nodes:
                    # if node.score == score:
                    file.write(f"{self.cve_id},{node.url},{node.score}\n")


# tracer1 = Tracer()
# print(tracer1.is_patch_node('https://github.com/crewjam/saml/commit/814d1d9c18457deeda08cbda2d38f79bedccfa62'))
# print(tracer1.is_patch_node('https://github.com/crewjam/saml/pull/140/commits/55d682de6bbefc17e979db16292f115467916919'))

file_path = "./input.txt"
with open(file_path, "r") as file:
    for line in file:
        tracer = Tracer(line.strip())
        print(tracer.cve_id)
        tracer.crawl()
        tracer.draw()
