from Crypto.Util.number import long_to_bytes
import math
n = 31698460634924412577399959706905435239651
e = 65537
c = 23648999580642514140599125257944114844209

p = 101
q = 313846144900241708687128313929756784551
assert p*q == n
phi = (p-1)*(q-1)
assert math.gcd(phi, e) == 1
d = pow(e, -1, phi)
pt = pow(c, d, n)
print(long_to_bytes(pt))