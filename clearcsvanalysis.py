#Program to clear the csv file
f = open("csvanalysis.csv", "w")
f.truncate()
f.close()