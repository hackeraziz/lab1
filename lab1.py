import re
import json
import csv
from collections import defaultdict

# Log məlumatları birbaşa skriptdə verilmişdir
log_data_text = """192.168.1.10 - - [05/Dec/2024:10:15:45 +0000] "POST /login HTTP/1.1" 200 5320
192.168.1.11 - - [05/Dec/2024:10:16:50 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.15 - - [05/Dec/2024:10:17:02 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:18:10 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:19:30 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:20:45 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.16 - - [05/Dec/2024:10:21:03 +0000] "GET /home HTTP/1.1" 200 3020"""

# JSON və mətn faylları üçün adlar
failed_logins_file = "failed_logins.json"
threat_ips_file = "threat_ips.json"
combined_security_data_file = "combined_security_data.json"
log_analysis_text_file = "log_analysis.txt"
log_analysis_csv_file = "log_analysis.csv"

# Log faylının oxunması və analiz üçün regex tərtibatı
log_pattern = re.compile(r"(?P<ip>\d+\.\d+\.\d+\.\d+).+\[(?P<date>\d+/\w+/\d+:\d+:\d+:\d+).+\"(?P<method>GET|POST|PUT|DELETE|HEAD).+\" (?P<status>\d+)")
failed_login_status = "401"

# Fayldan IP ünvanlarını, tarixləri və HTTP metodlarını çıxarış
ip_attempts = defaultdict(int)
log_data = []
for line in log_data_text.splitlines():
    log_match = log_pattern.search(line)
    if log_match:
        ip = log_match.group("ip")
        date = log_match.group("date")
        method = log_match.group("method")
        status = log_match.group("status")
        log_data.append({"ip": ip, "date": date, "method": method, "status": status})
        if status == failed_login_status:
            ip_attempts[ip] += 1

# 5-dən çox uğursuz giriş cəhdi olan IP-lərin seçilməsi
failed_logins = {ip: count for ip, count in ip_attempts.items() if count > 5}

# Təhdid kəşfiyyatı IP-lərini simulyasiya etmək üçün nümunə siyahı
threat_intelligence_ips = ["192.168.1.11", "10.0.0.15"]
threat_ips = [ip for ip in ip_attempts if ip in threat_intelligence_ips]

# Təhdidlər və uğursuz giriş məlumatlarının birləşdirilməsi
combined_security_data = {
    "failed_logins": failed_logins,
    "threat_ips": threat_ips
}

# Uğursuz girişlərin JSON faylına yazılması
with open(failed_logins_file, "w") as json_file:
    json.dump(failed_logins, json_file, indent=4)

# Təhdid IP-lərinin JSON faylına yazılması
with open(threat_ips_file, "w") as json_file:
    json.dump(threat_ips, json_file, indent=4)

# Birləşdirilmiş məlumatların JSON faylına yazılması
with open(combined_security_data_file, "w") as json_file:
    json.dump(combined_security_data, json_file, indent=4)

# Log analiz nəticələrinin mətn faylına yazılması
with open(log_analysis_text_file, "w") as text_file:
    for ip, count in failed_logins.items():
        text_file.write(f"IP Ünvanı: {ip}, Uğursuz Cəhdlər: {count}\n")

# CSV faylının yaradılması
with open(log_analysis_csv_file, "w", newline="") as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["IP Ünvanı", "Tarix", "HTTP Metodu", "Status", "Uğursuz Cəhdlər"])
    for log_entry in log_data:
        ip = log_entry["ip"]
        date = log_entry["date"]
        method = log_entry["method"]
        status = log_entry["status"]
        failed_attempts = failed_logins.get(ip, 0)
        csv_writer.writerow([ip, date, method, status, failed_attempts])

print("Log analizi tamamlandı və nəticələr fayllara yazıldı.")
