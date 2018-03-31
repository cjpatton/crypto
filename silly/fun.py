#p = (1<<64) - 189
p = (1<<32) - 5
a = 2
d = 3

# Finding square roots in the field.
assert (p % 4) == 3
b = 2343
x = b ** ((p + 1)>>2)
x %= p # = sqrt(b)

