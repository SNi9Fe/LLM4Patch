import requests
import re
import json
import os
from bs4 import BeautifulSoup
import graph
from urllib.parse import urljoin, urlparse, urlunparse
import pyecharts.options as opts
from pyecharts.charts import Graph as PyGraph


class Tracer:
    def __init__(self):
        self.reference_network = graph.Graph()

    def remove_anchor_from_url(self, url):
        parsed_url = urlparse(url)
        parsed_url = parsed_url._replace(fragment="")
        # Remove the anchor from the parsed URL
        cleaned_url = urlunparse(parsed_url)
        return cleaned_url

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

    def extract_urls_from_json(self, Json_data):
        # Extract urls from NVD Json feeds
        urls = []
        for cve_entry in Json_data["CVE_Items"]:
            if cve_entry["cve"]["CVE_data_meta"]["ID"] == cve_id:
                references = cve_entry["cve"]["reference_data"]
                for ref in references:
                    urls.append(ref["url"])
                break

        cleaned_url_list = {self.remove_anchor_from_url(url) for url in urls}
        return cleaned_url_list

    def extract_urls_from_debian_list(self):
        urls = []
        with open("./debian/list", "r") as file:
            lines = file.readlines()
            # 转换为迭代器对象
            lines_iter = iter(lines)

        for line in lines_iter:
            if cve_id in line:
                line = next(lines_iter)
                while "CVE" not in line:
                    if "NOTE:" in line and "https:" in line:
                        pattern = r"(https?://\S+)"
                        match = re.search(pattern, line)
                        if match:
                            # print(match.group(0))
                            url = match.group(0)
                            url = self.remove_anchor_from_url(url)
                            urls.append(url)

                    line = next(lines_iter)
                break

        return urls

    def extract_urls_from_redhat(self,Json):

        urls = []
        try:
            bug_id=Json["bugs"]
        except (KeyError, TypeError) as e:
            return []
        
        for bug_id in Json["bugs"]:
            for comment in Json["bugs"][bug_id]["comments"]:
                # print(comment["text"])
                pattern = r"(https?://\S+)"
                for url in re.findall(pattern, comment["text"]):
                    url = self.remove_anchor_from_url(url)
                    urls.append(url)

        return urls

    def request_redhat_advisory(self):
    # Request Red Hat advisory using the WebService API
        api_key = "GASfh0PvO6Jcu7JINAci7FippjWqC6C2LEAfTZf7"
        url = f"https://bugzilla.redhat.com/rest/bug/{cve_id}/comment"
        headers = {
            "Content-Type": "application/json;charset=UTF-8",
            "Authorization": f"Bearer {api_key}"
        }
        
        try:
            response = requests.get(url,headers=headers)
        except requests.exceptions.RequestException as e:
            # print("Request Error: ", e)
            return None
        
        Json = response.json()
        return Json

    def request_nvd_advisory(self):
        # Parse NVD advisory from NVD Json feeds

        # Get the Json file path
        year = cve_id.split("-")[1]
        file_name = f"nvdcve-{year}-preprocessed.json"
        script_path = os.path.abspath(__file__)
        current_directory = os.path.dirname(script_path)
        folder_path = os.path.join(current_directory, "nvd-Json-feeds")
        file_path = os.path.join(folder_path, file_name)

        # Load the Json file
        with open(file_path, "r") as Json_file:
            advisory = json.load(Json_file)
        return advisory

   

    def request_and_parse_advisories(self):
    # Request and parse advisories from NVD, Debian, and Red Hat
        nvd_advisory = self.request_nvd_advisory()
        debian_advisory = ""
        redhat_advisory = self.request_redhat_advisory()

        # Extract URL references from each advisory and add them as child nodes
        self.extract_and_add_url_references("NVD", nvd_advisory)
        self.extract_and_add_url_references("Debian", debian_advisory)
        self.extract_and_add_url_references('Red Hat', redhat_advisory)


    def initialize_reference_network(self):
        # Initialize the reference network with the CVE as the root node
        self.reference_network.add_node("root", "")

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

    def check_hybrid_and_repo(self, now, url, type):
        if type == "hybrid":
            return True
        url1_parse = urlparse(self.reference_network.nodes[now].url)
        url2_parse = urlparse(url)
        if (
            url1_parse.netloc == url2_parse.netloc
            and url1_parse.path.split("/")[1] != url2_parse.path.split("/")[1]
        ):
            return True
        return False

    def check_repeat_patch(self, url1, url2):
        netloc1 = urlparse(url1).netloc
        netloc2 = urlparse(url2).netloc
        sha1 = url1.split("/")[-1]
        sha2 = url2.split("/")[-1]
        if netloc1 == netloc2 and sha1 == sha2:
            return True

    def add_node_and_edge(self, url, now, strict=False, edge_type="reference"):
        type, url = self.classify_reference_nodes(url)
        new_node_id = -1
        for node in self.reference_network.nodes:
            if url == node.url:
                new_node_id = node.id
                if strict and self.check_hybrid_and_repo(now, url, node.type):
                    return
                break
            elif type == "patch" and node.type == "patch" and self.check_repeat_patch(
                url, node.url
            ):
                new_node_id = node.id
                break
        if new_node_id == -1:
            # strict:hybrid不要，不是同一个仓库的不要
            if strict and self.check_hybrid_and_repo(now, url, type):
                return
            if type != "useless":
                self.reference_network.add_node(type, url)
                new_node_id = self.reference_network.node_cnt - 1

        if new_node_id != -1 and new_node_id != now:
            self.reference_network.add_edge(edge_type, now, new_node_id)

    def extract_and_add_url_references(self, source_node, advisory):
        # Extract URL references from the advisory and add them as child nodes
        url_references = []

        if source_node == "NVD":
            url_references = self.extract_urls_from_json(advisory)

            # test is useless patch func:add a patch node which changes no source code file(.md)
            # self.reference_network.add_node('reference', 'https://github.com/RT-Thread/rt-thread/commit/cede0a3615b9ea1fb5942afaf7e6a62262ba5df2')
            # self.reference_network.add_edge(1,self.reference_network.node_cnt-1)
            for url in url_references:
                self.add_node_and_edge(url, 1)
        elif source_node == "Debian":
            # Extract URL references from the "Notes" field of Debian advisory
            url_references = self.extract_urls_from_debian_list()
            for url in url_references:
                self.add_node_and_edge(url, 2)

        elif source_node == "Red Hat":
            # Extract URL references from the "comments" field of Red Hat advisory
            url_references = self.extract_urls_from_redhat(advisory)
            for url in url_references:
                self.add_node_and_edge(url, 3)

        # Add URL references as child nodes of the corresponding advisory source node
        # for url in url_references:
        #     self.reference_network[cve_id]['children'].append({'type': 'reference', 'source': source_node, 'url': url})

    def is_patch_node(self, url):
        # Check if the reference node is a patch node
        # github_url_pattern = r'https://github\.com/[\w-]+/[\w-]+/commit/[a-zA-Z0-9]+'
        github_url_pattern = r"https://github\.com/[\w-]+/[\w-]+/(pull/\d+/)?(commit|commits)/[a-zA-Z0-9]+"
        svn_url_pattern = r"http(s)?://[\w.-]+/[\w/.-]+/!svn/commit/\d+"
        patch_pattern_1 = r"https?://(?:www\.)?(?:git\.videolan\.org|git\.libav\.org)/\?p=[^;]+;a=commit;h=[a-zA-Z0-9]+"
        return re.match(github_url_pattern, url) or re.match(svn_url_pattern, url) or re.match(patch_pattern_1, url)

    def is_issue_node(self, url):
        # Check if the reference node is an issue node
        github_issue_pattern = r"https://github\.com/[\w-]+/[\w-]+/issues/\d+"
        gitlab_issue_pattern = r"https://gitlab\.com/[\w-]+/[\w-]+/-/issues/\d+"
        github_PR_pattern = r"https://github\.com/[\w-]+/[\w-]+/pull/\d+"
        issue_keywords = ["bugzilla", "jira", "issues", "bugs", "tickets", "tracker"]
        issue_identifier_pattern = r"^[a-zA-Z]+-[0-9]+$"
        url_splits = url.split('/')
        # remove ""
        url_splits = [part for part in url_splits if part]
        if (
            re.match(github_issue_pattern, url)
            or re.match(gitlab_issue_pattern, url)
            or re.match(github_PR_pattern, url)
            or ( any(keyword in url for keyword in issue_keywords) and any(re.match(issue_identifier_pattern,url_part) for url_part in url_splits) )

        ):
            url = self.remove_anchor_from_url(url)
            url = self.remove_trail_from_url(url)
            return url
        return None

   
    def get_commit_modified_files(self, commit_url):
        # 提取出 commit 的 SHA 值
        # print(commit_url)
        commit_sha = commit_url.split("/")[-1]
        repo = commit_url.split("/")[4]
        owner = commit_url.split("/")[3]
        # 发送 GET 请求获取 commit 的详细信息
        api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"
        headers = {"Authorization": f"Token {github_token}"}
        # print(api_url)
        try:
            response = requests.get(api_url, headers=headers, timeout=10)
        except requests.exceptions.RequestException as e:
            # print("Request Error: ", e)
            return []

        try:
            commit_data = response.json()
            files = commit_data["files"]
        except (KeyError, TypeError) as e:
            # print("KeyError: ", e)
            files = []

        modified_files = [file["filename"] for file in files]
        return modified_files

    def is_useless_patch(self, patch_URL):
        modified_files_list = self.get_commit_modified_files(patch_URL)

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

    def get_links(self, now):
        # print(
        #     now,
        #     self.reference_network.nodes[now].id,
        #     self.reference_network.nodes[now].type,
        #     self.reference_network.nodes[now].url,
        # )
        url = self.reference_network.nodes[now].url
        try:
            response = requests.get(url, timeout=10)
            # print(response.status_code)
            response.raise_for_status()  # 抛出HTTPError异常
        except requests.exceptions.RequestException as e:
            # print( url )
            # print("Request Error: ", e)
            return
        soup = BeautifulSoup(response.content, "html.parser")

        # <code>标签中的不要
        for index,link in enumerate([a for a in soup.findAll("a") if not a.findParent("pre")]):
            if index > 20:
                break
            # 拼接url
            href = urljoin(url, link.get("href"))
            # remove anchor
            href = self.remove_anchor_from_url(href)
            self.add_node_and_edge(href, now, True)

    def reference_analysis(self, now, dep):
        if self.reference_network.vis[now] or dep >= 4:
            return
        self.reference_network.vis[now] = True
        type = self.reference_network.nodes[now].type
        if type == "hybrid" or type == "issue":
            self.get_links(now)
        edge_id = self.reference_network.head[now]
        while edge_id != None:
            to = self.reference_network.edges[edge_id].to
            self.reference_analysis(to, dep + 1)
            edge_id = self.reference_network.edges[edge_id].next

    def reference_augmentation(self):
        # Reference augmentation using GitHub API
        # Access token for GitHub API
        # /search/commits
        api_url = f"https://api.github.com/search/commits?q={cve_id}"
        headers = {"Authorization": f"Token {github_token}"}
        # print(api_url)
        try:
            response = requests.get(api_url, headers=headers, timeout=10)
        except requests.exceptions.RequestException as e:
            # print("Request Error: ", e)
            pass


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
        draw.render('./cve_graph_html/' + cve_id + ".html")

    def calc_score(self, now, dep):
        if self.reference_network.nodes[now].type == "patch":
            self.reference_network.nodes[now].score += 1.0 / (2.0 ** (dep - 1.0))
        edge_id = self.reference_network.head[now]
        while edge_id != None:
            to = self.reference_network.edges[edge_id].to
            if self.reference_network.nodes[now].type == "NVD":
                self.calc_score(to, dep)
            else:
                self.calc_score(to, dep + 1)
            edge_id = self.reference_network.edges[edge_id].next

    def crawl(self):
        # Entry point of the crawler
        self.initialize_reference_network()
        self.request_and_parse_advisories()
        self.reference_analysis(0, 0)
        self.reference_augmentation()
        self.calc_score(0, 0)
        sorted_nodes = sorted(self.reference_network.nodes, key=lambda node: node.score, reverse=True)
        score = sorted_nodes[0].score
        if score > 0:
            with open('./cve_patch.csv', "a") as file:
                for node in sorted_nodes:
                    if node.score == score:
                        file.write(f"{cve_id},{node.url},{node.score}\n")

# tracer1 = Tracer()
# print(tracer1.is_patch_node('https://github.com/crewjam/saml/commit/814d1d9c18457deeda08cbda2d38f79bedccfa62'))
# print(tracer1.is_patch_node('https://github.com/crewjam/saml/pull/140/commits/55d682de6bbefc17e979db16292f115467916919'))


github_token = ""
file_path = "./input.txt"
with open(file_path, "r") as file:
    for line in file:
        tracer = Tracer()
        # Remove trailing newline characters and spaces.
        cve_id = line.strip()
        print(cve_id)
        tracer.crawl()
        tracer.draw()
