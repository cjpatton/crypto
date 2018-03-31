#p = (1<<64) - 189
p = (1<<32) - 5

for x in range(2,10000000):
    if ((p-1) % x) == 0:
        print x
