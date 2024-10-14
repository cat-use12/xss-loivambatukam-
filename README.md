# XSS Scanner

XSS Scanner adalah alat untuk mendeteksi kerentanan Cross-Site Scripting (XSS) di situs web menggunakan payload yang ditentukan. Skrip ini ditulis dalam Python.

## Prerequisites

Pastikan Anda memiliki Python dan pip terinstal. Kemudian, instal pustaka yang diperlukan dengan perintah berikut:

```bash
pip install requests lxml jsonpath-ng

run?
python xss_scanner.py <urls> <params> [options]

python xss_scanner.py http://example.com http://another.com id username --method GET OR POST --payloads payloads.txt --user-agent "Mozilla/5.0" --output results.log

how to use exam
python xss_scanner.py http://example.com http://another.com id username --method GET --payloads payloads.txt --user-agent "Mozilla/5.0" --output results.log

python xss_scanner.py http://example.com http://another.com id username --method GET --payloads payloads.txt --user-agent "Mozilla/5.0" --output results.log

