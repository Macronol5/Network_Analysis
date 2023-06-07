from scapy.all import *
import csv
import dnsapi

# Print the summary info for each packet
with open('dns_data.csv', 'w', newline='') as csvfile:
    fieldnames = ['DNS Names']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for packet in rdpcap('pesce1_10Lac.pcap'):
        data = packet.summary().split()
        if ('DNS' in data) and (len(data) == 9):
            if data[8][1] == 'b':
                dns = data[8][3:-2:]
            else:
                try:
                    dns = dnsapi.getdnsname(data[8])
                except socket.gaierror:
                    dns = "DNS not found"
            row = {
                'DNS Names': dns,
            }
            writer.writerow(row)