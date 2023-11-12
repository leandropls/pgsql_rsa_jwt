# RSA JWT Decoder Functions for PostgreSQL

## Overview
Row-level security (RLS) in PostgreSQL is a feature that enables the restriction of database records visibility and access based on the current user's permissions. Instead of relying on application-level security, RLS enforces access control directly at the database level for each query, which allows for more granular and robust data protection.

By integrating JSON Web Tokens (JWTs) with RLS, PostgreSQL can authenticate users and apply access control policies using the information within the JWTs. This ensures that only the appropriate data is accessible to authenticated users based on their credentials. Verifying JWTs at the database level enhances overall security by preventing unauthorized access due to potential vulnerabilities in the application layer, centralizing critical access control logic within the database itself.

While PostgreSQL is a powerhouse of a database, it lacks the native ability to validate JWTs using RSA signatures. This project provides a set of PL/pgSQL functions aimed at enabling PostgreSQL databases to validate JWTs signed with RSA keys. The functions included in this project support the RSA verification algorithms RS256, RS384, and RS512, allowing for the validation of JWTs at the database level.


## Features

- Validate RSA-signed JWTs within PostgreSQL.
- Support RS256, RS384, and RS512 signing algorithms.
- Centralized access control logic within the database.
- Usable with pgcrypto extension.

## Installation

To install the RSA JWT decoding functions in your PostgreSQL database, follow these steps:

1. Ensure you have the `pgcrypto` extension installed. If not, you can create it by running:

   ```sql
   CREATE EXTENSION pgcrypto;
   ```

2. Execute the SQL script `decode_rsa_jwt.sql` in your database. This will create the necessary functions for RSA JWT validation.

## Usage Example

To use the RSA JWT decoding functions, provide the JWT token and a JSON array of keys. The function `decode_rsa_jwt` returns the decoded JWT claims if the signature is valid, and null otherwise.

Here's an example of how to use the function:

```sql
SELECT decode_rsa_jwt(
    token := 'eyJraWQiOiJMYXNy...fbD5mt2VUgEIQ09LK2X5WvexGNXgwTHS2OEoADYEqlsXYW4nCKrfTnWytRqqN3QGogp2w',
    keys := jsonb_build_array(
        jwk_to_key('{"alg":"RS256","e":"AQAB","kid":"h5pxMYKBE+xzuBRuWsPl7Z6FEkJNDRQcxPkY+wJbXow=","kty":"RSA","n":"1MAoK9L...OKx5Q","use":"sig"}'::jsonb),
        jwk_to_key('{"alg":"RS256","e":"AQAB","kid":"LasrDwHasdaqE41aLs8MLZQ5BYQwKgPcs7N1GGt5Ysg=","kty":"RSA","n":"xCEddOF0-SFSM1yU...N3QGogp2w","use":"sig"}'::jsonb)
    )
);
```

Replace the `token` and keys with the appropriate JWT and key set for your application.

## License

This project is licensed under the MIT License.
