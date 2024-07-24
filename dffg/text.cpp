#include <iostream>

// Function to perform modular exponentiation efficiently using squaring
// by squaring. It returns (x ^ y) % n.
unsigned int mod_exp(unsigned int x, unsigned int y, unsigned int n) {
  unsigned int result = 1;
  x = x % n; // Handle overflow by taking the modulo first

  while (y > 0) {
    // If y is odd, multiply base with the result
    if (y & 1) {
      result = (result * x) % n;
    }

    // Efficiently square the base (y is even now)
    y >>= 1;  // Equivalent to y /= 2 (bitwise right shift)
    x = (x * x) % n;
  }

  return result;
}

int main() {
  unsigned int base = 35, exponent = 77, modulus = 83;
  std::cout << "Result of (" << base << "^" << exponent << ") % " << modulus << " is: " << mod_exp(base, exponent, modulus) << std::endl;
  return 0;
}
