import requests
import re
from bs4 import BeautifulSoup

PAGE_URL = "http://94.237.123.178:53130"


def get_html_of(url):
    resp = requests.get(url)

    if resp.status_code != 200:
        print(
            f"HTTP status code of {resp.status_code} returned, but 200 was expected. Exiting..."
        )
        exit(1)

    return resp.content.decode()


def count_occurrences_in(word_list):
    word_count: dict[str, int] = {}

    for word in word_list:
        if word not in word_count:
            word_count[word] = 1
        else:
            current_count = word_count.get(word)
            word_count[word] = current_count + 1  # type: ignore
    return word_count


def get_all_words_from(url):
    html = get_html_of(url)
    soup = BeautifulSoup(html, "html.parser")
    raw_text = soup.get_text()
    return re.findall(r"\w+", raw_text)


def get_top_words_from(all_words):
    occurrences = count_occurrences_in(all_words)
    return sorted(occurrences.items(), key=lambda item: item[1], reverse=True)


all_words = get_all_words_from(PAGE_URL)
top_words = get_top_words_from(all_words)

for i in range(10):
    print(top_words[i])
