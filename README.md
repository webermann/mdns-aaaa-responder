# mdns-aaaa-responder

Workaround für Fire-TV-Geräte (Fire OS), die das Heimnetz mit tausenden mDNS-Anfragen pro Sekunde fluten.

## Problem

- Der Fire TV fragt DNS-Namen wie `fritz-boxoben.fritz.box` fälschlich per mDNS ab (AAAA).
- Die FRITZ!Boxen antworten, allerdings mit `fritz-boxoben.local`. Wireshark zeigt dazu `[Unsolicited: True]`.
- Der Fire TV verwirft die Antwort, weil der Name nicht passt, und fragt sofort erneut, ohne Backoff.
- Das ergibt mehrere tausend Pakete pro Sekunde. Multicast wird im WLAN mit niedriger Basisrate gesendet und belegt dadurch die Airtime auf allen Mesh-Knoten, auch für fremde WLANs auf demselben Kanal.

Siehe auch: [Amazon Developer Community – repeated mDNS AAAA queries](https://community.amazondeveloper.com/t/possible-fire-os-networking-issue-repeated-mdns-aaaa-queries-2-600-mdns-packets-sec-can-overload-entire-local-networks/28820)

## Lösung

Der Dienst lauscht auf mDNS-AAAA-Anfragen nach Namen unterhalb von `fritz.box`. Die Adresse löst er per normalem
DNS bei der Fritzbox auf und antwortet dann mit **exakt dem gefragten Namen**, einer TTL von 3600 s und gesetztem Cache-Flush-Bit.
Der Fire TV übernimmt die Antwort in seinen Cache und hört auf zu fragen. Normaler `.local`-mDNS-Verkehr bleibt unberührt.
Pro Name antwortet der Dienst höchstens einmal pro Sekunde und verstärkt einen Sturm deshalb nicht.

Er benötigt nur die Python-Standardbibliothek (ab Python 3.9) und keine Root-Rechte.

## Installation

```bash
sudo mkdir -p /opt/mdns-aaaa-responder
sudo cp mdns_aaaa_responder.py README.md /opt/mdns-aaaa-responder/
sudo cp mdns-aaaa-responder.default /etc/default/mdns-aaaa-responder
sudo cp mdns-aaaa-responder.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mdns-aaaa-responder
journalctl -u mdns-aaaa-responder -f
```

Der Host muss per LAN im selben Netzsegment hängen. Läuft der Dienst in einem LXD-Container oder einer VM, muss deren Interface gebridged sein.

## Konfiguration

Die Optionen stehen in `/etc/default/mdns-aaaa-responder` (alle Optionen: `--help`):

| Option           | Default       | Bedeutung                                                     |
|------------------|---------------|---------------------------------------------------------------|
| `--dns-server`   | `192.168.1.1` | DNS-Server für die Auflösung                                  |
| `--domain`       | `fritz.box`   | Nur Namen unterhalb dieser Domain beantworten, mehrfach möglich |
| `--source`       | alle          | Nur Anfragen dieser IPv4 beantworten, mehrfach möglich        |
| `--iface-ip`     | Kernel        | IPv4 des LAN-Interfaces, nötig bei mehreren Interfaces (Docker-Bridges) |
| `--ttl`          | `3600`        | TTL der Antwort in s                                          |
| `--verbose`      | aus           | Debug-Log                                                     |

Nach einer Änderung: `sudo systemctl restart mdns-aaaa-responder`

## Einschränkungen

- Der Dienst arbeitet nur über IPv4-mDNS (`224.0.0.251`). Das reicht, um die Schleife zu stoppen.
- Liefert der DNS-Server für einen Namen kein AAAA, wird nicht geantwortet.
- Er beseitigt nur das Symptom. Die eigentlichen Fehler liegen in Fire OS und, beim falschen Namen in der Antwort, in FRITZ!OS.
