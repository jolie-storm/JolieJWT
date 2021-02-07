# JolieJWT

This module implements JWT creator or reader for Jolie ver 1.9.X and 1.10.X.

## Operarations 

|Operation name | Functionality | Note |
|---------------|---------------|------|
| setSigner| Set the signer for JWT  | Need a valid keystore/jsonkeystore | 
| setVerifier |  Set the unsigner for JWT | Need a valid public key /JWK |
| createJWToken | Create the JWT token ||
| readJWToken | Read the JWT token ||