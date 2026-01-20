from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt

# قائمة لتخزين عناوين الـ MAC للأجهزة التي تم العثور عليها لمنع التكرار
networks = set()

def packet_handler(pkt):
    # التأكد من أن الحزمة هي حزمة إرشاد (Beacon Frame) من راوتر
    if pkt.haslayer(Dot11Beacon):
        # استخراج عنوان MAC الخاص بالراوتر
        bssid = pkt[Dot11].addr2
        # استخراج اسم الشبكة (SSID)
        ssid = pkt[Dot11Elt].info.decode()
        
        try:
            dbm_signal = pkt.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        if bssid not in networks:
            networks.add(bssid)
            print(f"ID: {len(networks):<3} | SSID: {ssid:<20} | BSSID: {bssid:<18} | Signal: {dbm_signal}dBm")

print("جاري فحص الشبكات المجاورة... (اضغط Ctrl+C للإيقاف)")
print("-" * 70)

# بدء عملية القنص (Sniffing)
# ملاحظة: يجب أن تكون بطاقة الشبكة في وضع Monitor Mode في بعض الأنظمة
sniff(prn=packet_handler, timeout=20)

