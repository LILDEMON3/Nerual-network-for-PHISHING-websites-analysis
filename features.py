import requests
import re
from paterns import *
import urllib.parse
from bs4 import BeautifulSoup
import socket
import whois
import time
from datetime import datetime
import pandas as pd
import numpy as np


# feature 1: Using the IP Address
def check_ip(url):
    ipv4_check = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)
    ipv6_check = re.search(
        r'\A(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\Z',
        url)
    ip_check = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)
    hex_check = re.search(r'(0x[0-9a-fA-F]{8}|0x[0-9a-fA-F]{6})', url)
    if ip_check or hex_check or ipv4_check or ipv6_check:
        return -1
    else:
        return 1


# feature 2: Long URL to Hide the Suspicious Part
def url_length(url):
    if len(url) < 54:
        return 1
    elif 70 >= len(url) >= 54:
        return 0
    else:
        return -1
    # checked and good


# feature 3: Using URL Shortening Services
def url_shortening(url):
    match = re.search(shortening_services, url)
    return -1 if match else 1
    # checked and good


# feature 4: URL’s having “@” Symbol
def having_at_symbol(url):
    match = re.search('@', url)
    return -1 if match else 1
    # good and checked


# feature 5: Redirecting using “//”
def double_slash_Redirecting(url):
    last_double_slash = url.rfind('//')
    return -1 if last_double_slash > 6 else 1


# feature 6: Adding Prefix or Suffix Separated by (-) to the Domain
def prefix(url):
    match = re.search("_", url)
    match1 = re.search("-", url)
    return -1 if match or match1 else 1
    # checked and good


# feature 7: Sub Domain and Multi Sub Domains
def having_sub_domain(url):
    if check_ip(url) == -1:
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            url)
        pos = match.end()
        url = url[pos:]

    num_dots = [x.start() for x in re.finditer(r'\.', url)]
    if len(num_dots) <= 3:
        return 1
    elif len(num_dots) == 4:
        return 0
    else:
        return -1


# feature 8: HTTPS (Hyper Text Transfer Protocol with Secure Sockets Layer)
def httpS(url):
    if 'https' in url and check_http(url) != -1:
        return 1
    return -1

# feature 9: Domain Registration Length
def domain_registration_length(domain):
    try:

        expiration_date = domain.expration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        registration_length = 0
    except TypeError:
        expiration_date = domain.expiration_date[0]
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        registration_length = 0
    if expiration_date:
        registration_length = (expiration_date - today).days
    return -1 if registration_length / 365 <= 1 else 1


# feature 10: Favicon
def favicon(url):
    try:
        parsed = urllib.parse.urlparse(url)
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        favicon = soup.find('link', rel="icon", href=True)
        match = re.search(parsed.netloc, favicon['href'])
        return 1 if match else -1
    except:
        return -1


# feature 11: Using Non-Standard Port
def get_host_name(url):
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    return hostname


def non_standard_ports(hostname, ports):
    open_arr = []
    closed_arr = []
    for i in range(len(ports)):
        try:
            sock = socket.create_connection((hostname, ports[i]), timeout=0.01)
            if ports[i] in [80, 443]:
                pass
            else:
                open_arr.append(ports[i])
                sock.close()
        except socket.timeout:
            closed_arr.append(ports[i])
        except socket.error:
            closed_arr.append(ports[i])
    if len(open_arr) > 2:
        return -1
    return 1


# feature 12: The Existence of “HTTPS” Token in the Domain Part of the URL
def check_http(url):
    index = url.find("http")
    if index == -1:
        return 1
    else:
        if "http" in url[index + 4:] or "https" in url[index + 4:]:
            return -1
        else:
            return 1


# feature 13: Request URL

def request_url(url, domain):
    i = 0
    success = 0
    response = requests.get(url)
    soup = BeautifulSoup(response.text,'html.parser')
    for img in soup.find_all('img', src=True):
        dots = [x.start() for x in re.finditer(r'\.', img['src'])]
        if url in img['src'] or domain in img['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for audio in soup.find_all('audio', src=True):
        dots = [x.start() for x in re.finditer(r'\.', audio['src'])]
        if url in audio['src'] or domain in audio['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for embed in soup.find_all('embed', src=True):
        dots = [x.start() for x in re.finditer(r'\.', embed['src'])]
        if url in embed['src'] or domain in embed['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for i_frame in soup.find_all('i_frame', src=True):
        dots = [x.start() for x in re.finditer(r'\.', i_frame['src'])]
        if url in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    try:
        percentage = success / float(i) * 100
    except:
        return 1

    if percentage < 22.0:
        return 1
    elif 22.0 <= percentage < 61.0:
        return 0
    else:
        return -1
# def request_URL(url):
#     bad = []
#     parsed_url = urllib.parse.urlparse(url)
#     domain = parsed_url.netloc
#     page = requests.get(url).text
#     soup = BeautifulSoup(page, 'html.parser')
#     external_objects = soup.find_all(['img', 'video', 'audio'], src=True)
#     for obj in external_objects:
#         obj_url = urllib.parse.urlparse(obj['src'])
#         if obj_url.netloc != domain:
#             bad.append(1)
#     if len(bad) == 1:
#         return 0
#     if len(bad) == 0:
#         return 1
#     else:
#         return -1


# feature 14: URL of Anchor
def url_of_anchor(url, domain):
    sus = []
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    anchors = soup.find_all('a', href=True)
    for anchor in anchors:
        match = re.search('youtube', anchor['href'])
        if '#' in anchor['href'] or 'skip' in anchor['href'] or 'Javascript' in anchor['href'] or 'javascript' in \
                anchor['href'] or '/' in anchor['href']:
            sus.append(1)
        elif not match:
            sus.append(1)
        else:
            pass

    if len(sus) == 1:
        return 0
    elif len(sus) == 0:
        return 1
    else:
        return -1


# feature 15: Links in <Meta>, <Script> and <Link> tags
def links_in_tags(url, domain):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    i = 0
    success = 0
    for link in soup.find_all('link', href=True):
        if url in link['href'] or domain in link['href']:
            success = success + 1
        i = i + 1

    for script in soup.find_all('script', src=True):
        if url in script['src'] or domain in script['src']:
            success = success + 1
        i = i + 1
    try:
        percentage = success / float(i) * 100
    except:
        return 1

    if percentage < 17.0:
        return 1
    elif 17.0 <= percentage < 81.0:
        return 0
    else:
        return -1


# feature 16: Server Form Handler (SFH)
def sfh(url, hostname):
    request = requests.get(url)
    soup = BeautifulSoup(request.text, 'html.parser')
    for form in soup.find_all('form', action=True):
        if form['action'] == "" or form['action'] == "about:blank":
            return -1
        elif url not in form['action'] and hostname not in form['action']:
            return 0
        else:
            return 1
    return 1


# feature 17: Submitting Information to Email
def submitting_to_email(url):
    request = requests.get(url)
    soup = BeautifulSoup(request.text, 'html.parser')
    for form in soup.find_all('form', action=True):
        return -1 if "mailto:" in form['action'] else 1
    return 1


# feature 18: Abnormal URL
def abnormal_url(hostname, url):
    match = re.search(hostname, url)
    return 1 if match else -1


# feature 19: Website Forwarding


def website_forwarding(url):
    session = requests.Session()
    session.max_redirects = 10
    response = session.head(url, allow_redirects=True)
    foward_count = len(response.history)
    if foward_count >= 3:
        return 0
    else:
        return 1

    # checked and good


# feature 20: Status Bar Customization
def status_bar(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    match = re.search(r'window.status', soup.text)
    if match:
        return -1
    else:
        return 1


# feature 21: Disabling Right Click
def check_right_click(url):
    try:
        response = requests.get(url)
        if "event.preventDefault" in response.text:
            return -1
        else:
            return 1
    except:
        return -1


# feature 22: Using Pop-up Window
def popup(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    scripts = soup.find_all('script')
    for script in scripts:
        match = re.search('window.open', script.text)
        if match:
            return -1
    return 1


# checked and good
# feature 23:IFrame Redirection
def iframe_rediraction(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    iframes = soup.find_all('iframe')
    match = False
    for iframe in iframes:
        for atribute, value in iframe.attrs.items():
            if atribute == "width":
                if value == "0":
                    match = True
            if atribute == "height":
                if value == "0":
                    match = True
            if atribute == "frameBorder":
                if value == "0":
                    match = True
            if atribute == "hidden":
                match = True
            if atribute == "style":
                if re.search("height:0", atribute):
                    match = True
                if re.search("width:0", atribute):
                    match = True
    if match:
        return -1
    return 1


# feature 24: Age of Domain
def age_of_domain(domain):
    try:
        creation_date = domain.creation_date[0]
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        creation_length = 0
    except TypeError:
        creation_date = domain.creation_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        creation_length = 0
    if creation_date:
        creation_length = (today - creation_date).days
    return -1 if creation_length <= 1500 else 1


# feature 25: DNS Record
# finished
# feature 26: Website Traffic (alexa top 1 million)
def web_traffic(url):
    if url_shortening(url) == -1:
        return -1
    try:
        rank = BeautifulSoup(requests.get("http://data.alexa.com/data?cli=10&dat=s&url=" + url).content, "xml").find(
            "REACH")['RANK']
    except TypeError:
        return -1
    rank = int(rank)
    if rank < 10000:
        return True
    return 1 if rank < 100000 else 0


# feature 27: PageRank

# feature 28: Google Index
# feature 29: Number of Links Pointing to Page

# feature 30: Statistical-Reports Based Feature
def stat_rep(url, hostname):
    try:
        ip = socket.gethostbyname(hostname)
    except:
        return -1
    ip_patern = r"146.112.61.108|31.170.160.61|67.199.248.11|67.199.248.10|69.50.209.78192.254.172.78|23.234.229.68|173.212.223.160|60.249.179.122| 146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42"
    url_pattern = r"at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly|esy\.es|hol.\es|000webhostapp\.com|16mb\.com|bit\.ly|for-our\.info|beget\.tech|blogspot\.com|weebly\.com|raymannag\.ch"
    match_i = re.search(ip, ip_patern)
    match_u = re.search(url, url_pattern)
    if match_i:
        return -1
    elif match_u:
        return -1

    return 1


def main(url):
    data = []
    hostname = get_host_name(url)
    data.append(check_ip(url))
    data.append(url_length(url))
    data.append(url_shortening(url))
    data.append(having_at_symbol(url))
    data.append(double_slash_Redirecting(url))
    data.append(prefix(url))
    data.append(having_sub_domain(url))
    data.append(-1 if url_shortening(url) == -1 else httpS(url))
    dns = 1
    try:
        domain = whois.whois(hostname)
    except:
        dns = -1
    data.append(-1 if dns == -1 else domain_registration_length(domain))
    data.append(favicon(url))
    data.append(non_standard_ports(hostname , [21,22,23,80,443,445,1433,1521,3306,3389]))
    data.append(check_http(url))
    data.append(request_url(url , hostname))
    data.append(url_of_anchor(url , hostname))
    data.append(links_in_tags(url , hostname))
    data.append(sfh(url , hostname))
    data.append(submitting_to_email(url))
    data.append(-1 if dns == -1 else abnormal_url(hostname, url))
    data.append(website_forwarding(url))
    data.append(status_bar(url))
    data.append(check_right_click(url))
    data.append(popup(url))
    data.append(iframe_rediraction(url))
    data.append(-1 if dns == -1 else age_of_domain(domain))
    data.append(dns)
    data.append(web_traffic(url))
    data.append(-1 if web_traffic(url) == -1 else 1)
    data.append(-1 if web_traffic(url) == -1 else 1)
    data.append(-1 if web_traffic(url) == -1 else 1)
    data.append(stat_rep(url , hostname))
    if web_traffic(url) == True:
        return [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]

    return data


def pandas_frame(data):
    dict = {"having_IP_Address" : None,
            "URL_Length" : None,
            "Shortining_Service" : None,
            "having_At_Symbol" : None,
            "double_slash_redirecting" : None,
            "Prefix_Suffix" : None,
            "having_Sub_Domain" : None,
            "SSLfinal_State" : None,
            "Domain_registeration_length" : None,
            "Favicon" : None,
            "port" : None,
            "HTTPS_token" : None,
            "Request_URL" : None,
            "URL_of_Anchor" : None,
            "Links_in_tags" : None,
            "SFH" : None,
            "Submitting_to_email" : None,
            "Abnormal_URL" : None,
            "Redirect" : None,
            "on_mouseover" : None,
            "RightClick" : None,
            "popUpWidnow" : None,
            "Iframe" : None,
            "age_of_domain" : None,
            "DNSRecord" : None,
            "web_traffic" : None,
            "Page_Rank" : None,
            "Google_Index" : None,
            "Links_pointing_to_page" : None,
            "Statistical_report" : None
            }
    arr = list(dict.keys())
    for i in range(len(data)):
        items = dict.keys()
        dict[arr[i]] = data[i]
    pw = pd.DataFrame(dict , index=[0])
    return pw


pandas_frame(main("https://tiny.one/track-ISL"))