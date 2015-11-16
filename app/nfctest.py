import serial
import time

ser = serial.Serial('/dev/pts/32', 57600)

with open('trace.txt', 'r') as f:
    for line in f:
        print(line)
        ser.write(line)
        time.sleep(1)

ser.close()
