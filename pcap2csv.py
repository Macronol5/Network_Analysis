from scapy.all import *
import csv


# Print the summary info for each packet
with open('savefile.csv', 'w', newline='') as csvfile:
    fieldnames = ['Time', 'Source IP','Source Port', 'Destination','Destination Port']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for packet in rdpcap('pesce1_10Lac.pcap'):
        if packet.summary()[-1] == "w":
            (source,destination) = (packet.summary().split()[5],packet.summary().split()[7])
            try:
                row = {
                        'Time': packet.time,
                        'Source IP': source.split(":")[0],
                        'Source Port': source.split(":")[1],
                        'Destination': destination.split(":")[0],
                        'Destination Port': destination.split(":")[1]
                }
                writer.writerow(row)
            except:
                writer.writerow({
                    'Time': packet.time,
                    'Source IP': "",
                    'Source Port': "",
                    'Destination': "",
                    'Destination Port': ""
                })