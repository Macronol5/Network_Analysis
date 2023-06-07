import csv
from ipcheck import is_private_ip

with open('savefile.csv', 'r', newline='') as csvfile:
    data = list(csv.reader(csvfile))

    with open('Public_IP.csv', 'w', newline='') as savefile:
        fieldnames = ['Source Public IP','Destination Public IP']
        writer = csv.DictWriter(savefile, fieldnames=fieldnames)
        writer.writeheader()

        S_IP = 0
        D_IP = 0
        lsts = set()
        lstd = set()

        stks = []
        stkd = []

        for lines in data[1:]:
            if is_private_ip(lines[1]) == False and lines[1] not in lsts:
                lsts.add(lines[1])
                stks.append(lines[1])
            if is_private_ip(lines[3]) == False and lines[3] not in lstd:
                lstd.add(lines[3])
                stkd.append(lines[3])
            if stks and stkd:
                row = {
                    'Source Public IP': stks.pop(0),
                    'Destination Public IP': stkd.pop(0)
                }
                writer.writerow(row)
        while stks:
            row = {
                'Source Public IP': stks.pop(0),
            }
            writer.writerow(row)
        while stkd:
            row = {
                'Destination Public IP': stkd.pop(0),
            }
            writer.writerow(row)


