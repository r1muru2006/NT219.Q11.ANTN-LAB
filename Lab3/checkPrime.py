from Crypto.Util.number import isPrime
for _ in range(3):
    p = int(input("Enter your prime: "))
    if isPrime(p):
        print(f"{p} is a prime")
    else:
        print(f"{p} is not a prime")