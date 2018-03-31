#p = (1<<64) - 189
p = (1<<32) - 5
a = 1
d = 19

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
