import re
import socket
import requests
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime

# HELPER FUNCTION: Mengambil domain utama (www.google.co.id -> google.co.id)
def get_base_domain(url_or_host):
    parsed = urlparse(url_or_host)
    host = parsed.netloc if parsed.netloc else url_or_host
    host = host.split(':')[0] # Hapus port jika ada
    
    parts = host.split('.')
    if len(parts) > 2:
        # Menangani double extension seperti .co.id, .com.au, .ac.id, dll.
        if parts[-2] in ['co', 'com', 'org', 'net', 'go', 'ac', 'or', 'sch', 'web'] and len(parts[-1]) <= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return host

def extract_features(url):
    features = []

    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    scheme = parsed.scheme
    hostname_base = get_base_domain(hostname)

    # --- KONEKSI NETWORK TUNGGAL ---
    response = None
    html_content = ""
    soup = None
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
    except:
        pass

    domain_info = None
    try:
        domain_info = whois.whois(hostname)
    except:
        pass

    dns_resolved = False
    try:
        socket.gethostbyname(hostname)
        dns_resolved = True
    except:
        pass


    # --- EKSTRAKSI FITUR (Standard UCI Phishing Dataset Mapping) ---

    # 1. UsingIP (Ada IP -> Phishing (1), Tidak ada IP -> Legitimate (-1))
    try:
        socket.inet_aton(hostname)
        features.append(1)
    except:
        features.append(-1)

    # 2. LongURL (Pendek < 54 -> Legitimate (-1), Sedang -> Suspicious (0), Panjang >= 75 -> Phishing (1))
    url_len = len(url)
    if url_len < 54:
        features.append(-1)
    elif 54 <= url_len <= 75:
        features.append(0)
    else:
        features.append(1)

    # 3. ShortURL (Pakai shortener -> Phishing (1), sebaliknya -> Legitimate (-1))
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co']
    features.append(1 if any(s in url for s in shorteners) else -1)

    # 4. Symbol@ (Ada @ -> Phishing (1), sebaliknya -> Legitimate (-1))
    features.append(1 if '@' in url else -1)

    # 5. Redirecting (// di akhir skema -> Phishing (1), sebaliknya -> Legitimate (-1))
    last_double_slash = url.rfind('//')
    features.append(1 if last_double_slash > 7 else -1)

    # 6. PrefixSuffix- (Ada '-' di hostname -> Phishing (1), sebaliknya -> Legitimate (-1))
    features.append(1 if '-' in hostname else -1)

    # 7. SubDomains (Banyak subdomain -> Phishing (1), Sedang -> Suspicious (0), Sedikit/Tidak ada -> Legitimate (-1))
    temp_host = hostname.replace("www.", "")
    dots = temp_host.count('.')
    if dots <= 1:
        features.append(-1)
    elif dots == 2:
        features.append(0)
    else:
        features.append(1)

    # 8. HTTPS (Menggunakan HTTPS -> Legitimate (1), sebaliknya -> Phishing (-1))
    features.append(1 if scheme == 'https' else -1)

    # 9. DomainRegLen (Registrasi pendek -> Phishing (-1), sebaliknya -> Legitimate (1))
    if domain_info:
        try:
            expiration = domain_info.expiration_date
            creation = domain_info.creation_date
            if isinstance(expiration, list): expiration = expiration[0]
            if isinstance(creation, list): creation = creation[0]
            age = (expiration - creation).days if expiration and creation else 0
            features.append(1 if age >= 365 else -1)
        except:
            features.append(-1)
    else:
        features.append(1 if dns_resolved else -1)

    # 10. Favicon (Favicon dari domain luar -> Phishing (-1), sebaliknya -> Legitimate (1))
    if soup:
        try:
            icon_tag = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
            if icon_tag and icon_tag.get('href'):
                icon_host = urlparse(icon_tag['href']).netloc
                if icon_host and get_base_domain(icon_host) != hostname_base:
                    features.append(-1)
                else:
                    features.append(1)
            else:
                features.append(1)
        except:
            features.append(-1)
    else:
        features.append(-1)

    # 11. NonStdPort (Pakai port non-standar -> Phishing (-1), sebaliknya -> Legitimate (1))
    features.append(-1 if ':' in hostname else 1)

    # 12. HTTPSDomainURL (Ada kata 'https' di hostname -> Phishing (-1), sebaliknya -> Legitimate (1))
    features.append(-1 if 'https' in hostname else 1)

    # 13. RequestURL (% link eksternal tinggi -> Phishing (-1), sedang -> Suspicious (0), rendah -> Legitimate (1))
    if soup:
        try:
            tags = soup.find_all(['img', 'audio', 'embed', 'iframe'], src=True)
            total = len(tags)
            offsite = 0
            for t in tags:
                src_host = urlparse(t['src']).netloc
                if src_host and get_base_domain(src_host) != hostname_base:
                    offsite += 1
            pct = (offsite / total * 100) if total > 0 else 0
            if pct < 22:
                features.append(1)
            elif 22 <= pct < 61:
                features.append(0)
            else:
                features.append(-1)
        except:
            features.append(-1)
    else:
        features.append(-1)

    # 14. AnchorURL (% anchor eksternal/kosong tinggi -> Phishing (-1), sedang -> Suspicious (0), rendah -> Legitimate (1))
    if soup:
        try:
            anchors = soup.find_all('a', href=True)
            total = len(anchors)
            offsite = 0
            for a in anchors:
                href = a['href']
                href_host = urlparse(href).netloc
                if href.startswith('#') or href.startswith('javascript') or 'void(0)' in href:
                    offsite += 1
                elif href_host and get_base_domain(href_host) != hostname_base:
                    offsite += 1
            pct = (offsite / total * 100) if total > 0 else 0
            if pct < 31:
                features.append(1)
            elif 31 <= pct < 67:
                features.append(0)
            else:
                features.append(-1)
        except:
            features.append(-1)
    else:
        features.append(-1)

    # 15. LinksInScriptTags (% eksternal tinggi -> Phishing (-1), sedang -> Suspicious (0), rendah -> Legitimate (1))
    if soup:
        try:
            total = 0
            offsite = 0
            for t in soup.find_all(['link', 'script', 'meta']):
                url_val = t.get('href') or t.get('src')
                if url_val:
                    total += 1
                    t_host = urlparse(url_val).netloc
                    if t_host and get_base_domain(t_host) != hostname_base:
                        offsite += 1
            pct = (offsite / total * 100) if total > 0 else 0
            if pct < 17:
                features.append(1)
            elif 17 <= pct < 81:
                features.append(0)
            else:
                features.append(-1)
        except:
            features.append(-1)
    else:
        features.append(-1)

    # 16. ServerFormHandler (SFH eksternal -> Phishing (-1), sedang -> Suspicious (0), internal -> Legitimate (1))
    if soup:
        try:
            forms = soup.find_all('form', action=True)
            if not forms:
                features.append(1)
            else:
                sfh_status = 1
                for f in forms:
                    action = f['action']
                    if action == "" or action.lower() == "about:blank":
                        sfh_status = -1
                        break
                    action_host = urlparse(action).netloc
                    if action_host and get_base_domain(action_host) != hostname_base:
                        sfh_status = 0
                features.append(sfh_status)
        except:
            features.append(-1)
    else:
        features.append(-1)

    # 17. InfoEmail (Ada mailto -> Phishing (-1), sebaliknya -> Legitimate (1))
    if html_content:
        features.append(-1 if "mailto:" in html_content.lower() or "mail(" in html_content.lower() else 1)
    else:
        features.append(-1)

    # 18. AbnormalURL (Hostname tidak sesuai WHOIS -> Phishing (-1), sebaliknya -> Legitimate (1))
    if domain_info:
        try:
            features.append(1 if domain_info.domain_name else -1)
        except:
            features.append(-1)
    else:
        features.append(1 if dns_resolved else -1)

    # 19. WebsiteForwarding (Redirect >= 4 -> Phishing (1), sebaliknya -> Legitimate (0))
    if response:
        try:
            features.append(1 if len(response.history) >= 4 else 0)
        except:
            features.append(0)
    else:
        features.append(0)

    # 20. StatusBarCust (window.status diubah -> Phishing (-1), sebaliknya -> Legitimate (1))
    if html_content:
        features.append(-1 if "window.status" in html_content else 1)
    else:
        features.append(-1)

    # 21. DisableRightClick (Right click dimatikan -> Phishing (-1), sebaliknya -> Legitimate (1))
    if html_content:
        features.append(-1 if "event.button==2" in html_content or "preventDefault()" in html_content else 1)
    else:
        features.append(-1)

    # 22. UsingPopupWindow (Ada prompt/alert -> Phishing (-1), sebaliknya -> Legitimate (1))
    if html_content:
        features.append(-1 if "prompt(" in html_content.lower() or "alert(" in html_content.lower() else 1)
    else:
        features.append(-1)

    # 23. IframeRedirection (Ada iframe -> Phishing (-1), sebaliknya -> Legitimate (1))
    if soup:
        try:
            iframes = soup.find_all('iframe')
            features.append(-1 if len(iframes) > 0 else 1)
        except:
            features.append(-1)
    else:
        features.append(-1)

    # 24. AgeofDomain (Umur domain < 6 bulan -> Phishing (-1), sebaliknya -> Legitimate (1))
    if domain_info:
        try:
            creation = domain_info.creation_date
            if isinstance(creation, list): creation = creation[0]
            age_days = (datetime.now() - creation).days if creation else 0
            features.append(1 if age_days >= 180 else -1)
        except:
            features.append(-1)
    else:
        features.append(1 if dns_resolved else -1)

    # 25. DNSRecording (DNS tidak terdaftar -> Phishing (-1), sebaliknya -> Legitimate (1))
    features.append(1 if dns_resolved else -1)

    # 26. WebsiteTraffic (Default Suspicious (0))
    features.append(0)

    # 27. PageRank (Default Legitimate (1))
    features.append(1 if dns_resolved else -1)

    # 28. GoogleIndex (Tidak ada di indeks Google -> Phishing (-1), sebaliknya -> Legitimate (1))
    features.append(1 if dns_resolved else -1)

    # 29. LinksPointingToPage (Default Legitimate (1))
    features.append(1 if dns_resolved else -1)

    # 30. StatsReport (Default Legitimate (1))
    features.append(1)

    return features

# import re
# import socket
# import requests
# import whois
# from urllib.parse import urlparse
# from bs4 import BeautifulSoup
# from datetime import datetime

# # HELPER FUNCTION: Mengambil domain utama (misal: www.google.co.id -> google.co.id)
# def get_base_domain(url_or_host):
#     parsed = urlparse(url_or_host)
#     host = parsed.netloc if parsed.netloc else url_or_host
#     host = host.split(':')[0] # Hapus port jika ada
    
#     parts = host.split('.')
#     if len(parts) > 2:
#         # Menangani double extension seperti .co.id, .com.au, .ac.id, dll.
#         if parts[-2] in ['co', 'com', 'org', 'net', 'go', 'ac', 'or', 'sch', 'web'] and len(parts[-1]) <= 3:
#             return ".".join(parts[-3:])
#         return ".".join(parts[-2:])
#     return host

# def extract_features(url):
#     features = []

#     # Parsing URL awal
#     parsed = urlparse(url)
#     hostname = parsed.netloc
#     path = parsed.path
#     scheme = parsed.scheme
    
#     # Dapatkan domain utama dari target URL
#     hostname_base = get_base_domain(hostname)

#     # --- SATUKAN KONEKSI NETWORK DI AWAL ---
#     # 1. HTTP Request Tunggal
#     response = None
#     html_content = ""
#     soup = None
#     try:
#         response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
#         html_content = response.text
#         soup = BeautifulSoup(html_content, 'html.parser')
#     except:
#         pass

#     # 2. WHOIS Request Tunggal
#     domain_info = None
#     try:
#         domain_info = whois.whois(hostname)
#     except:
#         pass

#     # 3. DNS Check Tunggal
#     dns_resolved = False
#     try:
#         socket.gethostbyname(hostname)
#         dns_resolved = True
#     except:
#         pass


#     # --- EKSTRAKSI FITUR ---

#     # 1. UsingIP
#     try:
#         socket.inet_aton(hostname)
#         features.append(1)
#     except:
#         features.append(0)

#     # 2. LongURL (>=75)
#     features.append(1 if len(url) >= 75 else 0)

#     # 3. ShortURL
#     shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co']
#     features.append(1 if any(s in url for s in shorteners) else 0)

#     # 4. Symbol@
#     features.append(1 if '@' in url else 0)

#     # 5. Redirecting (//)
#     features.append(1 if url.count('//') > 2 else 0)

#     # 6. PrefixSuffix-
#     features.append(1 if '-' in hostname else 0)

#     # 7. SubDomains
#     features.append(1 if hostname.count('.') > 2 else 0)

#     # 8. HTTPS
#     features.append(1 if scheme == 'https' else 0)

#     # 9. DomainRegLen (panjang masa registrasi domain)
#     if domain_info:
#         try:
#             expiration = domain_info.expiration_date
#             creation = domain_info.creation_date
#             if isinstance(expiration, list): expiration = expiration[0]
#             if isinstance(creation, list): creation = creation[0]
#             age = (expiration - creation).days if expiration and creation else 0
#             features.append(1 if age >= 365 else 0)
#         except:
#             features.append(0)
#     else:
#         # DNS Fallback: Jika WHOIS gagal tapi DNS aktif, asumsikan normal
#         features.append(1 if dns_resolved else 0)

#     # 10. Favicon (ada link icon di tag head?)
#     if soup:
#         try:
#             icon = soup.find("link", rel=lambda x: x and 'icon' in x.lower()) is not None
#             features.append(1 if icon else 0)
#         except:
#             features.append(0)
#     else:
#         features.append(0)

#     # 11. NonStdPort (pakai port eksplisit)
#     features.append(1 if ':' in hostname else 0)

#     # 12. HTTPSDomainURL (https dalam hostname)
#     features.append(1 if 'https' in hostname else 0)

#     # 13. RequestURL (image/script pointing to other domain)
#     if soup:
#         try:
#             imgs = soup.find_all('img', src=True)
#             total = len(imgs)
#             offsite = 0
#             for i in imgs:
#                 src_host = urlparse(i['src']).netloc
#                 if src_host and get_base_domain(src_host) != hostname_base:
#                     offsite += 1
#             features.append(1 if total > 0 and offsite / total > 0.5 else 0)
#         except:
#             features.append(0)
#     else:
#         features.append(0)

#     # 14. AnchorURL
#     if soup:
#         try:
#             anchors = soup.find_all('a', href=True)
#             total = len(anchors)
#             offsite = 0
#             for a in anchors:
#                 href_host = urlparse(a['href']).netloc
#                 if href_host and get_base_domain(href_host) != hostname_base:
#                     offsite += 1
#             features.append(1 if total > 0 and offsite / total > 0.5 else 0)
#         except:
#             features.append(0)
#     else:
#         features.append(0)

#     # 15. LinksInScriptTags
#     if soup:
#         try:
#             scripts = soup.find_all('script', src=True)
#             links = 0
#             for s in scripts:
#                 src_host = urlparse(s['src']).netloc
#                 if src_host and get_base_domain(src_host) != hostname_base:
#                     links += 1
#             features.append(1 if links > 3 else 0)
#         except:
#             features.append(0)
#     else:
#         features.append(0)

#     # 16. ServerFormHandler
#     if soup:
#         try:
#             forms = soup.find_all('form', action=True)
#             bad = 0
#             for f in forms:
#                 action = f['action']
#                 action_host = urlparse(action).netloc
#                 if action.startswith("http") and action_host and get_base_domain(action_host) != hostname_base:
#                     bad += 1
#             features.append(1 if bad > 0 else 0)
#         except:
#             features.append(0)
#     else:
#         features.append(0)

#     # 17. InfoEmail (ada email di URL)
#     features.append(1 if re.search(r'[a-zA-Z0-9._%+-]+@', url) else 0)

#     # 18. AbnormalURL (hostname not in WHOIS)
#     if domain_info:
#         try:
#             features.append(0 if domain_info.domain_name else 1)
#         except:
#             features.append(1)
#     else:
#         # DNS Fallback: Jika WHOIS gagal tapi DNS aktif, asumsikan domain normal (0)
#         features.append(0 if dns_resolved else 1)

#     # 19. WebsiteForwarding (response.history panjang)
#     if response:
#         try:
#             features.append(1 if len(response.history) > 2 else 0)
#         except:
#             features.append(0)
#     else:
#         features.append(0)

#     # 20. StatusBarCust (tidak bisa dicek)
#     features.append(0)

#     # 21. DisableRightClick (JS)
#     features.append(0)

#     # 22. UsingPopupWindow
#     if response:
#         try:
#             popups = "popup" in html_content.lower()
#             features.append(1 if popups else 0)
#         except:
#             features.append(0)
#     else:
#         features.append(0)

#     # 23. IframeRedirection
#     if soup:
#         try:
#             iframes = soup.find_all('iframe')
#             features.append(1 if len(iframes) > 0 else 0)
#         except:
#             features.append(0)
#     else:
#         features.append(0)

#     # 24. AgeofDomain (umur domain)
#     if domain_info:
#         try:
#             creation = domain_info.creation_date
#             if isinstance(creation, list): creation = creation[0]
#             age_days = (datetime.now() - creation).days if creation else 0
#             features.append(1 if age_days > 180 else 0)
#         except:
#             features.append(0)
#     else:
#         # DNS Fallback: Jika WHOIS gagal tapi DNS aktif, asumsikan domain lama (1)
#         features.append(1 if dns_resolved else 0)

#     # 25. DNSRecording
#     features.append(1 if dns_resolved else 0)

#     # 26. WebsiteTraffic (tidak tersedia langsung)
#     features.append(0)

#     # 27. PageRank (tidak tersedia langsung)
#     features.append(0)

#     # 28. GoogleIndex (apakah diindex oleh google)
#     features.append(0)

#     # 29. LinksPointingToPage (jumlah backlink)
#     features.append(0)

#     # 30. StatsReport (tidak tersedia)
#     features.append(0)

#     return features

# import re
# import socket
# import requests
# import whois
# from urllib.parse import urlparse
# from bs4 import BeautifulSoup
# from datetime import datetime

# def extract_features(url):
#     features = []

#     # Parsing URL
#     parsed = urlparse(url)
#     hostname = parsed.netloc
#     path = parsed.path
#     scheme = parsed.scheme

#     # 1. UsingIP
#     try:
#         socket.inet_aton(hostname)
#         features.append(1)
#     except:
#         features.append(0)

#     # 2. LongURL (>=75)
#     features.append(1 if len(url) >= 75 else 0)

#     # 3. ShortURL
#     shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co']
#     features.append(1 if any(s in url for s in shorteners) else 0)

#     # 4. Symbol@
#     features.append(1 if '@' in url else 0)

#     # 5. Redirecting (//)
#     features.append(1 if url.count('//') > 2 else 0)

#     # 6. PrefixSuffix-
#     features.append(1 if '-' in hostname else 0)

#     # 7. SubDomains
#     features.append(1 if hostname.count('.') > 2 else 0)

#     # 8. HTTPS
#     features.append(1 if scheme == 'https' else 0)

#     # 9. DomainRegLen (panjang masa registrasi domain)
#     try:
#         domain_info = whois.whois(hostname)
#         expiration = domain_info.expiration_date
#         creation = domain_info.creation_date
#         if isinstance(expiration, list): expiration = expiration[0]
#         if isinstance(creation, list): creation = creation[0]
#         age = (expiration - creation).days if expiration and creation else 0
#         features.append(1 if age >= 365 else 0)
#     except:
#         features.append(0)

#     # 10. Favicon (ada link icon di tag head?)
#     try:
#         response = requests.get(url, timeout=5)
#         soup = BeautifulSoup(response.text, 'html.parser')
#         icon = soup.find("link", rel=lambda x: x and 'icon' in x.lower()) is not None
#         features.append(1 if icon else 0)
#     except:
#         features.append(0)

#     # 11. NonStdPort (pakai port eksplisit)
#     features.append(1 if ':' in hostname else 0)

#     # 12. HTTPSDomainURL (https dalam hostname)
#     features.append(1 if 'https' in hostname else 0)

#     # 13. RequestURL (image/script pointing to other domain)
#     try:
#         soup = BeautifulSoup(requests.get(url).text, 'html.parser')
#         imgs = soup.find_all('img', src=True)
#         total = len(imgs)
#         offsite = len([i for i in imgs if urlparse(i['src']).netloc not in hostname])
#         features.append(1 if total > 0 and offsite / total > 0.5 else 0)
#     except:
#         features.append(0)

#     # 14. AnchorURL
#     try:
#         anchors = soup.find_all('a', href=True)
#         total = len(anchors)
#         offsite = len([a for a in anchors if urlparse(a['href']).netloc not in hostname])
#         features.append(1 if total > 0 and offsite / total > 0.5 else 0)
#     except:
#         features.append(0)

#     # 15. LinksInScriptTags
#     try:
#         scripts = soup.find_all('script', src=True)
#         links = len([s for s in scripts if urlparse(s['src']).netloc not in hostname])
#         features.append(1 if links > 3 else 0)
#     except:
#         features.append(0)

#     # 16. ServerFormHandler
#     try:
#         forms = soup.find_all('form', action=True)
#         bad = 0
#         for f in forms:
#             action = f['action']
#             if action.startswith("http") and hostname not in action:
#                 bad += 1
#         features.append(1 if bad > 0 else 0)
#     except:
#         features.append(0)

#     # 17. InfoEmail (ada email di URL)
#     features.append(1 if re.search(r'[a-zA-Z0-9._%+-]+@', url) else 0)

#     # 18. AbnormalURL (hostname not in WHOIS)
#     try:
#         domain_info = whois.whois(hostname)
#         features.append(0 if domain_info.domain_name else 1)
#     except:
#         features.append(1)

#     # 19. WebsiteForwarding (response.history panjang)
#     try:
#         response = requests.get(url, timeout=5)
#         features.append(1 if len(response.history) > 2 else 0)
#     except:
#         features.append(0)

#     # 20. StatusBarCust (tidak bisa dicek)
#     features.append(0)

#     # 21. DisableRightClick (JS)
#     features.append(0)

#     # 22. UsingPopupWindow
#     try:
#         popups = "popup" in response.text.lower()
#         features.append(1 if popups else 0)
#     except:
#         features.append(0)

#     # 23. IframeRedirection
#     try:
#         iframes = soup.find_all('iframe')
#         features.append(1 if len(iframes) > 0 else 0)
#     except:
#         features.append(0)

#     # 24. AgeofDomain (umur domain)
#     try:
#         domain_info = whois.whois(hostname)
#         creation = domain_info.creation_date
#         if isinstance(creation, list): creation = creation[0]
#         age_days = (datetime.now() - creation).days if creation else 0
#         features.append(1 if age_days > 180 else 0)
#     except:
#         features.append(0)

#     # 25. DNSRecording
#     try:
#         socket.gethostbyname(hostname)
#         features.append(1)
#     except:
#         features.append(0)

#     # 26. WebsiteTraffic (tidak tersedia langsung)
#     features.append(0)

#     # 27. PageRank (tidak tersedia langsung)
#     features.append(0)

#     # 28. GoogleIndex (apakah diindex oleh google)
#     features.append(0)

#     # 29. LinksPointingToPage (jumlah backlink)
#     features.append(0)

#     # 30. StatsReport (tidak tersedia)
#     features.append(0)

#     return features
