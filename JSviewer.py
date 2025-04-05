import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import csv
import os
import argparse

def get_script_urls(page_url):
    try:
        response = requests.get(page_url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"[!] Не удалось загрузить страницу {page_url}: {e}")
        return []
    soup = BeautifulSoup(response.text, 'html.parser')
    script_tags = soup.find_all('script', src=True)
    return [urljoin(page_url, tag['src']) for tag in script_tags]

def extract_domains_from_js(js_code):
    urls = re.findall(r'https?://[^\s"\'<>]+', js_code)
    return set(urlparse(url).netloc.lower() for url in urls)

def load_blacklist(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        print(f"[!] Файл {filename} не найден!")
        return set()

def load_sites(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Файл {filename} не найден!")
        return []

def analyze_site(site_url, blacklist):
    results = []
    script_urls = get_script_urls(site_url)

    for script_url in script_urls:
        domain = urlparse(script_url).netloc.lower()
        script_name = urlparse(script_url).path.split('/')[-1] or '[root]'

        # Опасный источник
        if domain in blacklist:
            results.append((site_url, script_url, 'Опасный источник', domain))
            continue

        try:
            response = requests.get(script_url, timeout=10)
            response.raise_for_status()
            js_code = response.text
            domains = extract_domains_from_js(js_code)
            bad_domains = domains.intersection(blacklist)
            for bad_domain in bad_domains:
                results.append((site_url, script_url, 'Обращение к запрещённому домену', bad_domain))
        except Exception as e:
            results.append((site_url, script_url, 'Ошибка загрузки скрипта', str(e)))

    return results

def save_to_csv(results, filename='results.csv'):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Сайт', 'Скрипт', 'Тип угрозы', 'Детали'])
        for row in results:
            writer.writerow(row)

def print_results(results):
    for row in results:
        print(f"\nСайт: {row[0]}\nСкрипт: {row[1]}\n⚠️  {row[2]}: {row[3]}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Анализатор скриптов на сайтах")
    parser.add_argument('--list', action='store_true', help='Проверить список сайтов из файла sites.txt')
    parser.add_argument('--csv', action='store_true', help='Сохранить результаты в CSV (results.csv)')
    args = parser.parse_args()

    blacklist = load_blacklist('blacklist.txt')
    all_results = []

    if args.list:
        sites = load_sites('sites.txt')
        print(f"[i] Проверка {len(sites)} сайтов из файла...")
        for site in sites:
            print(f"  — {site}")
            all_results.extend(analyze_site(site, blacklist))
    else:
        site = input("Введите URL сайта: ").strip()
        print(f"[i] Проверка сайта: {site}")
        all_results.extend(analyze_site(site, blacklist))

    if args.csv:
        save_to_csv(all_results, 'output/results.csv')
        print(f"\n✅ Результаты сохранены в output/results.csv")
    else:
        if all_results:
            print_results(all_results)
        else:
            print("✅ Подозрительных скриптов не найдено.")
