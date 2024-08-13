# rbal-cards-payment-cryptography
Repository for managing cryptographic keys using AWS Payment Cryptography service.

### ZMK

* RPC sends three components of the ZMK (Zone Master Key) in a TR-31 key block to three different individuals.
* Each person enters their own key component and validates the Check Character Value (CCV).

* The TR-31 key block is a standard format for representing encrypted key material. 

* For a ZMK with three components, we have:
    - Component 1: Encrypted ZMK Component 1
    - Component 2: Encrypted ZMK Component 2
    - Component 3: Encrypted ZMK Component 3

### ZPK

* RPC also sends ZPK (Zone Pin Key) that is encrypted with ZMK in TR-31 format D. 

* After importing ZPK, AWS Payment Cryptography will return ZPK KCV (Key Check Value) that has to be validated. 

## Understanding the Process

* Key Hierarchy: In payment cryptography, a ZPK encrypts PIN blocks. The ZPK itself is encrypted under a Zone Master Key (ZMK). This layered security ensures the protection of sensitive PIN data.
    
* Import Mechanism: AWS Payment Cryptography supports a standard-based electronic key exchange for importing ZPKs. We are using the ANSI X9.24 TR-31-2018 standard. This standard requires that a KEK (Key Encryption Key), which in our case is the ZMK, has already been established in AWS Payment Cryptography.