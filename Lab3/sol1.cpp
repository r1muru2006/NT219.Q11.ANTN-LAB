#include "bigint.h"
#include "genPrime.h"
#include <ctime>

using namespace std;

bigint pow(bigint base, bigint exp, bigint mod);

// 1. Prime numbers
// It's in genPrime.h

// 2. Greatest common divisor (using Euclidean Algorithm)
bigint myGCD(bigint a, bigint b) {
    if (a == to_bigint(0))
        return b;
    return myGCD(b % a, a);
}


// 3. Modular exponentiation
// function pow in genPrime.h


int main() {
    srand(time(NULL));
    cout << "This is my program related to Number Theory\n";
    while(true){
        int choice;
        cout << "\nHere is the menu selection:\n";
        cout << "1. PRIME NUMBERS\n";
        cout << "2. GREATEST COMMON DIVISOR\n";
        cout << "3. MODULAR EXPONENTIATION\n";
        cout << "4. Exit the program\n";
        cout << "Enter your choice (1, 2, 3, 4): "; cin >> choice;
        if(choice == 1){
            int bytelength;
            cout << "\n-------------PRIME NUMBERS-------------\n";
            cout << "--Generate random primes with bit-length--\n";
            cout << "Enter your byte selection: "; cin >> bytelength;
            bigint z = genPrime(bytelength);
            cout << "Here is your " << bytelength << "-byte prime number: " << z << endl;
            cout << "Check prime numbers: "; cin >> z;
            if(MillerRabin(z))
                cout << z << " is a prime number\n";
            else
                cout << z << " is not a prime number\n";
        } else if(choice == 2){
            bigint x, y;
            cout << "\n---GREATEST COMMON DIVISOR---\n";
            cout << "Enter first number: "; cin >> x;
            cout << "Enter second number: "; cin >> y;
            bigint res2 = myGCD(x, y);
            cout << "Result: gcd(" << x << ", " << y << ") = " << res2 << endl;
        } else if (choice == 3){
            bigint b, e, p;
            cout << "\n----MODULAR EXPONENTIATION----\n";
            cout << "Enter base: "; cin >> b;
            cout << "Enter exponent: "; cin >> e;
            cout << "Enter modulo: "; cin >> p;
            bigint res3 = pow(b, e, p);
            cout << "The value of " << b << "^" << e << " mod " << p << " is: " << res3 << endl;
        } else if (choice == 4){
            return 0;
        } else cout << "This is not a valid selection, please re-enter!!!\n";
    }
}