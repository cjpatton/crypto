#p = (1<<64) - 189
#p = (1<<32) - 5
p = (1<<33) - 9
a = 1
d = 17

# Cofactors?
for x in range(1,100000):
    if ((p-1) % x) == 0:
        print x

# Finding squares and non squarees in the field.
sq = []
nsq = []
assert (p % 4) == 3
for b in range(1,100):
    x = pow(b, (p + 1)/4, p)
    if b == ((x*x) % p):
        sq.append(b)
    else:
        nsq.append(b)

x = pow(p-1, (p+1)/4, p)
if ((x*x)%p) == (p-1):
    sq.append(p-1)
else:
    nsq.append(p-1)

print "squares", sq
print "non-squares", nsq
