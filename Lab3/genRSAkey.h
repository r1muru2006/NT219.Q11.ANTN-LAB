#include <bits/stdc++.h>
#include "bigint.h"

using namespace std;

bigint gcdExtended(bigint a, bigint b, bigint* x, bigint* y){
    if (a == to_bigint(0)) {
        *x = 0, *y = 1;
        return b;
    }

    bigint x1, y1;
    bigint gcd = gcdExtended(b % a, a, &x1, &y1);

    *x = y1 - (b / a) * x1;
    *y = x1;

    return gcd;
}

bigint inv(bigint A, bigint M){
    bigint x, y;
    bigint g = gcdExtended(A, M, &x, &y);
    bigint res = (x % M + M) % M;
    return res;
}


vector<pair<bigint, bigint>> create_RSA_key(bigint p, bigint q, bigint e){
    bigint n = p*q;
    bigint phi = (p - to_bigint(1))*(q - to_bigint(1));

    if(big_gcd(e, phi) != to_bigint(1)){
        cout << "e and phi are not coprime\n";
        return {};
    }
    
    if(e >= phi) {
        cout << "e must be less than phi\n";
        return {};
    }

    bigint d = inv(e, phi);
    vector<pair<bigint, bigint>> key;
    key.push_back({e, n}); // public key
    key.push_back({d, n}); // private key
    return key;
}