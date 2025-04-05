# JSwebscanner
A simple script to check JS-script on website and check them for requests to malicious sites from blacklist

![изображение](https://github.com/user-attachments/assets/590a8b55-ccc4-47e5-8a7f-38a49b73995e)

Usage:

1. Just check site: python script.py
2. Just check site and save as CSV:	python script.py --csv
3. Check sites from list:	python script.py --list {list_name.txt}
4. Check sites from list + CSV:	python script.py --list {list_name.txt} --csv

Requirements:

pip install requests beautifulsoup4

Blacklist.txt I borrowed from this great project: https://github.com/schooldropout1337/lazyegg/
but I strongly recommend to use ur own fresh one (4 example URLhaus: https://urlhaus.abuse.ch/downloads/text/)
Use wisely ^_^
