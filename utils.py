from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.edge.service import Service
from webdriver_manager.microsoft import EdgeChromiumDriverManager
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse, unquote
import time

def remove_anchor_from_url(url):
    parsed_url = unquote(url)
    parsed_url = urlparse(parsed_url)
    parsed_url = parsed_url._replace(fragment="")
    cleaned_url = urlunparse(parsed_url)
    return cleaned_url

def get_links(url):
    """
    使用 Selenium 和 Edge 浏览器爬取指定 URL 页面上的所有链接（包括动态加载内容）。
    
    参数:
        url (str): 要爬取的目标 URL。

    返回:
        list: 包含页面中所有链接的列表。
    """
    # 配置 Edge 浏览器和 WebDriver（无头模式）
    options = webdriver.EdgeOptions()
    options.add_argument("--headless")  # 无头模式，关闭显示
    options.add_argument("--disable-gpu")  # 禁用 GPU 加速（推荐）
    options.add_argument("--window-size=1920,1080")  # 设置窗口大小
    options.add_argument("--log-level=3")  # 屏蔽日志
    driver = webdriver.Edge(service=Service(EdgeChromiumDriverManager().install()), options=options)
    try:
        # 打开目标页面
        driver.get(url)

        # 滚动到底部多次以加载所有动态内容
        last_height = driver.execute_script("return document.body.scrollHeight")
        while True:
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(2)  # 等待页面加载
            new_height = driver.execute_script("return document.body.scrollHeight")
            if new_height == last_height:
                break  # 如果没有新的高度加载，退出循环
            last_height = new_height

        # 获取页面的完整 HTML
        html = driver.page_source
        soup = BeautifulSoup(html, "html.parser")

        # 提取所有链接
        all_links = []
        for a_tag in soup.find_all("a", href=True):
            full_url = urljoin(url, a_tag["href"])
            remove_anchor_from_url(full_url)
            if full_url not in all_links and full_url.startswith("http"):
                all_links.append(full_url)
        
        return all_links
    except Exception as e:
            print(f"Error opening {url}: {e}")
            return []
    finally:
        # 关闭浏览器
        driver.quit()

def draw_graph():
    pass

if __name__ == "__main__":
    target_url = "http://marc.info/?l=bugtraq&m=144050155601375&w=2"
    links = get_links(target_url)

    print("页面中的所有链接：")
    for link in links:
        print(link)
