import socket, requests, time, random, threading, os, ssl, re, json, html, sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from fpdf import FPDF

# Попытка импорта Scapy для локального сканирования
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_READY = True
except:
    SCAPY_READY = False

# ANSI Colors & UI Configuration
os.system("")
class Col:
    G = '\033[92m'; R = '\033[91m'; C = '\033[96m'; Y = '\033[93m'
    B = '\033[94m'; M = '\033[95m'; E = '\033[0m'; BOLD = '\033[1m'

class MortyOverlordV16:
    def __init__(self):
        self.target = ""; self.ip = ""; self.case_dir = ""
        self.report_data = []; self.risk = 0
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.ua})
        self.pdf_name = "Supreme_Audit_Report.pdf"
        self.homepage_hash = "" # Для борьбы с ложными срабатываниями

    def clear(self): os.system('cls' if os.name == 'nt' else 'clear')

    def log(self, console_msg, report_msg, color=Col.E, risk_val=0):
        self.risk += risk_val
        safe_msg = str(report_msg).encode('ascii', 'ignore').decode('ascii')
        self.report_data.append(safe_msg)
        print(f"{color}{console_msg}{Col.E}")

    def banner(self):
        self.clear()
        r_col = Col.G if self.risk < 50 else Col.Y if self.risk < 150 else Col.R
        print(f"""{Col.R}{Col.BOLD}
    ███╗   ███╗ ██████╗ ██████╗ ████████╗██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ████╗ ████║██    ██╗██   ██╗╚══██   ══╝╚██╗ ██╔╝██      ██     ██   ██╗████╗  ██║
    ██╔████╔██║██    ██║██████╔╝   ██   ║   ╚████╔╝ ███████╗██     ███████║██╔██╗ ██║
    ██║╚██╔╝██║██    ██║██   ██╗   ██   ║    ╚██╔╝  ╚    ██║██     ██   ██║██║╚██╗██║
    ██║ ╚═╝ ██║╚██████╔╝██   ██║   ██   ║     ██║   ███████║╚██████╗██   ██║██║ ╚████║
    ╚═╝     ╚═╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝     ╚═╝   ╚══════╝ ╚═════╝╚═╝   ╚═╝╚═╝  ╚═══╝
    {Col.E}{Col.G}         --- v16.0 "THE OVERLORD" | SUPREMACY EDITION ---
    {Col.E}Target: {Col.Y}{self.target: <25}{Col.E} | Risk: {r_col}{self.risk}{Col.E} | Cases: {Col.M}Active{Col.E}
    {Col.M}═══════════════════════════════════════════════════════════════════════════════{Col.E}""")

    def set_target(self):
        self.clear()
        print(f"\n{Col.C}[>] ВХОД В СИСТЕМУ OVERLORD...{Col.E}")
        url = input("Введите домен цели (напр. example.com): ").strip()
        self.target = url.replace("http://", "").replace("https://", "").split("/")[0]
        self.case_dir = os.path.join("cases", self.target)
        if not os.path.exists(self.case_dir): os.makedirs(self.case_dir)
        try:
            self.ip = socket.gethostbyname(self.target)
            print(f"{Col.G}[+] ЦЕЛЬ ПОДТВЕРЖДЕНА: {self.ip}{Col.E}")
            time.sleep(1)
        except: print(f"{Col.R}[-] ЦЕЛЬ В ОФФЛАЙНЕ ИЛИ DNS ОШИБКА.{Col.E}"); time.sleep(2)

    # --- МОДУЛЬ 1: ЛОКАЛЬНЫЙ ХИЩНИК ---
    def module_local_scan(self):
        self.banner()
        self.log("\n--- [ 1. LOCAL NETWORK SCAN ] ---", "--- [ 1. LOCAL NETWORK SCAN ] ---", Col.C)
        if not SCAPY_READY:
            print(f"{Col.R}[!] Scapy/Npcap не найдены. Локальный скан отключен.{Col.E}"); return
        try:
            print(f"{Col.Y}[*] Анализ домашней сети (ARP Map)...{Col.E}")
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1/24"), timeout=2, verbose=False)
            for _, r in ans: self.log(f"    [+] {r.psrc: <15} | MAC: {r.hwsrc}", f"Local Device: {r.psrc} ({r.hwsrc})")
        except: print("[-] Ошибка доступа к сетевому интерфейсу.")

    # --- МОДУЛЬ 2: ВНЕШНЯЯ РАЗВЕДКА ---
    def module_recon(self):
        self.banner()
        self.log("\n--- [ 2. ADVANCED WEB INTELLIGENCE ] ---", "--- [ 2. WEB INTELLIGENCE ] ---", Col.C)
        try:
            r = self.session.get(f"https://{self.target}", timeout=5)
            # Фикс кириллицы
            title_m = re.findall(r'<title>(.*?)</title>', r.text, re.IGNORECASE)
            title = html.unescape(title_m[0].strip()) if title_m else "No Title"
            self.log(f"[+] Title: {title}", f"Title: {title}")
            
            # Технологии
            h = r.headers
            srv = h.get('Server', 'Hidden')
            pwr = h.get('X-Powered-By', 'None')
            self.log(f"[+] Server: {srv} | Backend: {pwr}", f"Server: {srv} | Tech: {pwr}", risk_val=40 if "5.6" in pwr else 0)
            
            # WAF Detect
            if "ddos-guard" in srv.lower() or "cloudflare" in srv.lower():
                self.log(f"[!] WAF DETECTED: {srv}", f"WAF: {srv}", Col.Y, risk_val=5)

            # Сохранение заголовков
            with open(os.path.join(self.case_dir, "headers_audit.txt"), "w") as f: f.write(str(h))
        except: self.log("[-] Recon failed", "Recon error")

    # --- МОДУЛЬ 3: УМНЫЙ ФУЗЗЕР (БОРЬБА С ЛОЖНЫМИ ЦЕЛЯМИ) ---
    def module_smart_fuzzer(self):
        self.banner()
        self.log("\n--- [ 3. SMART SKELETON REAPER (ANTI-FAKE) ] ---", "--- [ 3. SMART FILE FUZZER ] ---", Col.C)
        
        # Запоминаем как выглядит "фейковый" ответ (главная страница)
        try:
            self.homepage_hash = self.session.get(f"https://{self.target}", timeout=3).text[:1000]
        except: pass

        paths = [".env", "config.php", "config.php.bak", "backup.sql", ".git/config", "database.sql", "info.php"]
        
        def check(p):
            try:
                res = self.session.get(f"https://{self.target}/{p}", timeout=2)
                if res.status_code == 200:
                    # Если контент совпадает с главной - это ложь (False Positive)
                    if res.text[:1000] == self.homepage_hash:
                        return 
                    
                    self.log(f"    [!!!] REAL EXPOSURE: /{p}", f"CRITICAL: /{p} is REAL", Col.R, 50)
                    with open(os.path.join(self.case_dir, f"leaked_{p.replace('/','_')}"), "wb") as out:
                        out.write(res.content[:10000])
            except: pass
            
        with ThreadPoolExecutor(max_workers=10) as ex: ex.map(check, paths)

    # --- МОДУЛЬ 4: ЛАБОРАТОРИЯ УЯЗВИМОСТЕЙ ---
    def module_vulns(self):
        self.banner()
        self.log("\n--- [ 4. VULNERABILITY LABORATORY ] ---", "--- [ 4. VULNERABILITY LAB ] ---", Col.C)
        # SQLi
        try:
            r = self.session.get(f"http://{self.target}/?id=1'", timeout=3)
            if any(x in r.text.lower() for x in ["sql syntax", "mysql", "native client"]):
                self.log("[!!!] SQL ERROR DETECTED!", "CRITICAL: SQLi vulnerability potential", Col.R, 60)
        except: pass
        # XSS
        payload = "<script>alert(1)</script>"
        try:
            r = self.session.get(f"http://{self.target}/?q={payload}", timeout=3)
            if payload in r.text:
                self.log("[!!!] XSS REFLECTION FOUND!", "CRITICAL: XSS vulnerability found", Col.R, 50)
        except: pass

    # --- МОДУЛЬ 5: ИНФРАСТРУКТУРА ---
    def module_infra(self):
        self.banner()
        self.log("\n--- [ 5. INFRASTRUCTURE & BANNERS ] ---", "--- [ 5. INFRASTRUCTURE SCAN ] ---", Col.C)
        ports = {21:"FTP", 22:"SSH", 80:"HTTP", 443:"HTTPS", 3306:"MySQL", 3389:"RDP"}
        for p, n in ports.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(1)
            if s.connect_ex((self.ip, p)) == 0:
                banner = ""
                try: s.send(b'\r\n'); banner = s.recv(512).decode(errors='ignore').strip()[:30]
                except: pass
                self.log(f"[+] Port {p} ({n}) OPEN | {banner}", f"Port {p} ({n}) OPEN | {banner}", Col.G, 10)
            s.close()

    # --- МОДУЛЬ 6: СТРЕСС-ТЕСТ (3 СТАДИИ) ---
    def module_stress(self):
        self.banner()
        self.log("\n--- [ 6. TRIPLE-STAGE STRESS TEST ] ---", "--- [ 6. STRESS WARFARE ] ---", Col.R)
        stages = [50, 100, 500]
        for count in stages:
            print(f"\n{Col.Y}[*] ЗАПУСК ВОЛНЫ: {count} ЗАПРОСОВ...{Col.E}")
            ok, fail = 0, 0
            def attack():
                nonlocal ok, fail
                try:
                    if self.session.get(f"https://{self.target}", timeout=1).status_code == 200: ok += 1
                    else: fail += 1
                except: fail += 1
            with ThreadPoolExecutor(max_workers=200) as ex:
                for _ in range(count): ex.submit(attack)
            res = f"STAGE {count} -> OK: {ok} | FAIL: {fail}"
            self.log(f"    [!] {res}", res, Col.Y if ok > 0 else Col.R)
            if ok == 0 and fail > 0: self.log(f"    [!!!] ЦЕЛЬ ЗАБЛОКИРОВАЛА СТАДИЮ {count}", f"Blocked at {count}", Col.R, 20)

    # --- МОДУЛЬ 7: ГЕНЕРАТОР ОТЧЕТОВ ---
    def generate_report(self):
        try:
            pdf = FPDF(); pdf.add_page(); pdf.set_font("helvetica", "B", 24)
            pdf.set_text_color(100, 0, 0)
            pdf.cell(0, 20, text="MORTYSCAN OVERLORD SUPREMACY REPORT", align='C', new_x="LMARGIN", new_y="NEXT")
            
            risk_lvl = "APOCALYPTIC" if self.risk > 200 else "CRITICAL" if self.risk > 120 else "HIGH" if self.risk > 70 else "MEDIUM"
            pdf.set_font("helvetica", "B", 16); pdf.set_text_color(200, 0, 0) if risk_lvl != "MEDIUM" else pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 10, text=f"THREAT VERDICT: {risk_lvl} ({self.risk} pts)", align='C', new_x="LMARGIN", new_y="NEXT")
            
            pdf.ln(5); pdf.set_font("courier", size=9); pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 10, text=f"Target: {self.target} ({self.ip}) | Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", align='C', new_x="LMARGIN", new_y="NEXT")
            pdf.ln(5)
            
            for line in self.report_data:
                if "---" in line: pdf.set_font("courier", "B", 11); pdf.set_text_color(0, 0, 150); pdf.ln(3)
                elif "!!!" in line: pdf.set_font("courier", "B", 10); pdf.set_text_color(200, 0, 0)
                else: pdf.set_font("courier", size=9); pdf.set_text_color(0, 0, 0)
                pdf.multi_cell(180, 5, text=line, new_x="LMARGIN", new_y="NEXT")
            
            p = os.path.join(self.case_dir, "Supreme_Report.pdf")
            pdf.output(p); pdf.output(self.pdf_name); os.startfile(self.pdf_name)
            print(f"\n{Col.G}[!!!] ВЕРДИКТ ВЫНЕСЕН. ОТЧЕТ: {p}{Col.E}")
        except Exception as e: print(f"PDF Error: {e}")

    def full_auto(self):
        self.report_data = []; self.risk = 0
        self.module_local_scan()
        self.module_recon()
        self.module_smart_fuzzer()
        self.module_vulns()
        self.module_infra()
        self.module_stress()
        self.generate_report()
        input("\nMission Accomplished. Press Enter...")

def main():
    tool = MortyOverlordV16()
    tool.set_target()
    while True:
        tool.banner()
        print(f"\n{Col.B}1.{Col.E} Change Target | {Col.B}2.{Col.E} Local Scan | {Col.B}3.{Col.E} Web Recon | {Col.B}4.{Col.E} Smart Fuzzer")
        print(f"{Col.B}5.{Col.E} Vuln Lab     | {Col.B}6.{Col.E} Infra Scan  | {Col.B}7.{Col.E} Warfare (Stress) | {Col.B}8.{Col.E} Report")
        print(f"{Col.R}[A] EXECUTE OVERLORD FULL SUPREMACY AUDIT{Col.E} | {Col.R}0. EXIT{Col.E}")
        c = input(f"\n{Col.BOLD}[MORTY-OVERLORD]>{Col.E} ").upper()
        if c == '1': tool.set_target()
        elif c == '2': tool.module_local_scan(); input("\nEnter...")
        elif c == '3': tool.module_recon(); input("\nEnter...")
        elif c == '4': tool.module_smart_fuzzer(); input("\nEnter...")
        elif c == '5': tool.module_vulns(); input("\nEnter...")
        elif c == '6': tool.module_infra(); input("\nEnter...")
        elif c == '7': tool.module_stress(); input("\nEnter...")
        elif c == '8': tool.generate_report()
        elif c == 'A': tool.full_auto()
        elif c == '0': break

if __name__ == "__main__":
    main()