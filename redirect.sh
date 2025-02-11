#!/bin/bash
# Mevcut NAT tablosu kurallarını temizleyin (dikkatli kullanın)
sudo iptables -t nat -F

# Port tanımları
HTTP_PORT=80
HTTPS_PORT=443
TCP_PORT=9020
UDP_PORT=9021
PROXY_HTTP=9015
PROXY_HTTPS=9043

echo "Bidirectional transparent proxy kuralları kuruluyor..."

### HTTP için
# Dışarıdan gelen trafiği PREROUTING zincirinde yönlendir (HTTP)
sudo iptables -t nat -A PREROUTING -p tcp --dport $HTTP_PORT -j REDIRECT --to-ports $PROXY_HTTP
# Yerel (OUTPUT) trafiği de yönlendir (HTTP)
sudo iptables -t nat -A OUTPUT -p tcp --dport $HTTP_PORT -j REDIRECT --to-ports $PROXY_HTTP

### HTTPS için
# Dışarıdan gelen HTTPS trafiğini PREROUTING zincirinde yönlendir
sudo iptables -t nat -A PREROUTING -p tcp --dport $HTTPS_PORT -j REDIRECT --to-ports $PROXY_HTTPS
# Yerel (OUTPUT) HTTPS trafiğini de yönlendir
sudo iptables -t nat -A OUTPUT -p tcp --dport $HTTPS_PORT -j REDIRECT --to-ports $PROXY_HTTPS

### UDP için
# Dışarıdan gelen UDP trafiğini PREROUTING zincirinde yönlendir
sudo iptables -t nat -A PREROUTING -p udp -j REDIRECT --to-port $UDP_PORT
# Yerel UDP trafiği için OUTPUT zincirinde yönlendirme (opsiyonel)
sudo iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-port $UDP_PORT

### Diğer TCP trafiği (HTTP/HTTPS dışındaki SYN paketleri)
# Dışarıdan gelen TCP SYN paketleri (80 ve 443 dışındaki) yönlendir
sudo iptables -t nat -A PREROUTING -p tcp ! --dport $HTTP_PORT ! --dport $HTTPS_PORT --syn -j REDIRECT --to-ports $TCP_PORT
# Yerel TCP SYN paketleri için OUTPUT zincirinde yönlendirme
sudo iptables -t nat -A OUTPUT -p tcp ! --dport $HTTP_PORT ! --dport $HTTPS_PORT --syn -j REDIRECT --to-ports $TCP_PORT

echo "iptables kuralları uygulandı:"
echo "  HTTP -> $PROXY_HTTP (PREROUTING & OUTPUT)"
echo "  HTTPS -> $PROXY_HTTPS (PREROUTING & OUTPUT)"
echo "  TCP -> $TCP_PORT (PREROUTING & OUTPUT)"
echo "  UDP -> $UDP_PORT (PREROUTING & OUTPUT)"
