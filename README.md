HCrypt
=====================================

[![Build Status](https://travis-ci.org/SHIN-Foundation/HCrypt.svg?branch=master)](https://travis-ci.org/SHIN-Foundation/HCrypt)

https://shin-foundation.github.io

What is HCrypt?
----------------

HCrypt is an experimental cryptography aesthetically based on BCrypt but developed to generate faster hash and lower memory cost.

Your body works with:
- Safe 176-bit salt randomization;
- Hash processing based on 288-bit data input size;
- Jump list in hexadecimal;
- And just for aesthetics, prefix hexadecimal 4 chars.

* (The prefix can be used for filtering).

License
-------

HCrypt is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

### Hash Composition

[PREFIX][JUMPS][TRUE HASH][SALT]
Char: 4.2.36.22
Total: 64 characters

### [PHP Example] Syntax Usage

```php
require_once('path/to/HCrypt.class.php');
$hako = new HCrypt();
echo $hako->_crypt();
//
  string _crypt ( string $data , [ int $jumps , [ string $salt , [ string $prefix ] ] ] )
    // 
    //  Parameters:
    //  $data: Input of the data to be encrypted. If no add data returns "n/a".
    //
    //  $jumps: Number of jumps for hashing. Calculation: 2^EXP; (Min: 4, Max: 16).
    //
    //  $salt: Salt input to avoid collisions. Input must have 22 characters (a-Z,0-9)!
    //  If not declared or if different from 22 chars, it randomly generates a salt of 22 characters.
    //
    //  $prefix: Converts string to hexadecimal prefix.
    // (Just for aesthetics, does not interfere hashing)!
    // *Can be used for filtering; Default: 0x48.
```
