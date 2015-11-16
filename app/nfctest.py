import serial
import time

with open('trace.txt', 'r') as f, serial.Serial('/dev/pts/31', 57600) as ser:
    for line in f:
        print(line)
        ser.write(line)
        time.sleep(1)
