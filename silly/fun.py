#p = (1<<64) - 189
#p = (1<<32) - 5
p = (1<<33) - 9
a = 1
d = 19

# Cofactors?
for x in range(1,100000):
    if ((p-1) % x) == 0:
        print x

# Finding square roots in the field.
sq = []
nsq = []
assert (p % 4) == 3
for b in range(1,100):
    x = pow(b, ((p + 1)/4), p)
    if b == ((x*x) % p):
        sq.append(b)
    else:
        nsq.append(b)

print sq
print nsq
