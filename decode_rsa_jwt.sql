/**
 * MIT License
 *
 * Copyright (c) 2023 Leandro Lima <leandro@lls-software.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * Converts bytea (binary string) data to a numeric representation.
 *
 * @param {bytea} bytea_data - The bytea binary string data to be converted into a numeric representation.
 * @returns {numeric} - The numeric representation of the input binary string data.
 */
create or replace function bytea_to_numeric(bytea_data bytea)
    returns numeric as
$$
declare
    result     numeric := 0; -- Initialized to hold the numeric result as we process bytes.
    byte_value int; -- Temporarily holds the numeric value of an individual byte.
begin
    -- Loop through each byte in the bytea data.
    for i in 1..length(bytea_data) loop
        -- Extract the byte value at the current position.
        byte_value := get_byte(bytea_data, i - 1);

        -- Accumulate the result, shifting left by one byte (8 bits) before adding new value.
        result := result * 256 + byte_value;
    end loop;

    -- Return the numeric representation of the bytea data.
    return result;
end;
$$ language plpgsql immutable strict;


/**
 * Converts a numeric value to a bytea (binary string) representation.
 *
 * @param {numeric} value - The numeric value to be converted into a bytea binary string representation.
 * @returns {bytea} - The bytea representation of the input numeric value.
 */
create or replace function numeric_to_bytea(value numeric)
    returns bytea as
$$
declare
    bytea_value bytea := '\x'; -- Initializes the result as an empty bytea string with the hex format introduced.
    remainder   integer; -- Stores the remainder of the numeric value after division by 256.
begin
    -- Loop while there is value left to process.
    while value > 0 loop
        -- Get the remainder of the value when divided by 256, representing the rightmost byte value.
        remainder := value % 256;

        -- Prepend the byte to the result with new remainder value.
        bytea_value := set_byte(('\x00' || bytea_value), 0, remainder);

        -- Divide the value by 256, effectively shifting right by one byte (preparing for next loop iteration).
        value := (value - remainder) / 256;
    end loop;

    -- Return the bytea representation of the numeric value.
    return bytea_value;
end;
$$ language plpgsql immutable strict;


/**
 * Decodes a URL-safe base64-encoded string into a bytea (binary) value.
 *
 * @param {text} segment - The URL-safe base64-encoded string to be decoded into binary data.
 * @returns {bytea} - The bytea (binary) value representing the decoded output from the input base64-encoded string.
 */
create or replace function urlsafe_b64decode(segment text)
    returns bytea as
$$
begin
    -- Replace URL-safe characters with standard base64 characters.
    segment := replace(replace(segment, '-', '+'), '_', '/');

    -- Apply padding to the segment to make length a multiple of 4 as required by base64.
    segment := rpad(segment, (ceil(length(segment) / 4::float) * 4)::integer, '='::text);

    -- Return the binary data decoded from the base64 string.
    return decode(segment, 'base64');
end;
$$ language plpgsql immutable;

/**
 * Converts a JSON Web Key (JWK) contained in a JWT to a key object.
 *
 * @param {jsonb} jwt - The JSON Web Token containing the JWK to be converted.
 * @returns {jsonb} - A key object derived from the JWK within the JWT, in JSONB format.
 */
create or replace function jwk_to_key(jwt jsonb)
    returns jsonb as
$$
begin
    return jsonb_build_object(
        'alg', jwt ->> 'alg',
        'e', bytea_to_numeric(urlsafe_b64decode(jwt ->> 'e')),
        'n', bytea_to_numeric(urlsafe_b64decode(jwt ->> 'n'))
    );
end;
$$ language plpgsql immutable strict;

/**
 * Calculates the bit length of a numeric value (how many bits are necessary to represent the number).
 *
 * @param {numeric} num - The numeric value for which the bit length is to be calculated.
 * @returns {int} - The number of bits required to represent the input numeric value.
 */
create or replace function bit_length(num numeric)
    returns int as
$$
begin
    -- A value of 0 still occupies one bit (the zero bit).
    if num = 0 then
        return 1;
    end if;

    -- Calculate and return the number of bits needed to represent 'num'.
    -- Logarithm base 2 of 'num', rounded down and incremented by 1.
    return floor(ln(num) / ln(2)) + 1;
end;
$$ language plpgsql immutable strict;


/**
 * Performs modular exponentiation, which calculates (base ^ exponent) % modulus.
 *
 * @param {numeric} base - The base number to be raised to the power of the exponent.
 * @param {int} exponent - The exponent to which the base number is to be raised.
 * @param {numeric} modulus - The modulus to be applied after the exponentiation.
 * @returns {numeric} - The result of (base ^ exponent) % modulus.
 */
create or replace function mod_exp(base numeric, exponent int, modulus numeric)
    returns numeric as
$$
declare
    result numeric := 1;
begin
    -- Ensure the base is within the modulus for further calculations
    base := base % modulus;

    -- Loop while there is still exponent value left.
    while exponent > 0 loop
        -- If current exponent bit is 1, accumulate result.
        if exponent % 2 = 1 then
            result := (result * base) % modulus;
        end if;

        -- Divide exponent by 2 for the next iteration (bit shift right).
        exponent := exponent / 2;

        -- Square the base for the next iteration and apply modulus.
        base := (base * base) % modulus;
    end loop;

    -- Return the result of the modular exponentiation.
    return result;
end;
$$ language plpgsql immutable strict;

/**
 * Decrypts a bytea (binary string) value using RSA modular exponentiation.
 *
 * @param {bytea} value - The bytea (binary string) value to be decrypted.
 * @param {int} e - The exponent in the RSA key.
 * @param {numeric} n - The modulus in the RSA key.
 * @returns {bytea} - The decrypted bytea (binary string) value.
 */
create or replace function decrypt_rsa(value bytea, e integer, n numeric)
    returns bytea as
$$
begin
    return numeric_to_bytea(
        value := mod_exp(
            base := bytea_to_numeric(value),
            exponent := e,
            modulus := n
        )
    );
end;
$$ language plpgsql immutable strict;

/**
 * Decodes a RSA-signed JWT (JSON Web Token) and verifies its signature against a JSON array of keys.
 *
 * @param {text} token - The RSA-signed JWT to be decoded and verified.
 * @param {jsonb} keys - The JSON array of keys provided in JSONB format, against which the JWT's signature will be verified.
 * @returns {jsonb} - The decoded JWT claims in JSONB format if the signature is valid, null otherwise.
 */
create or replace function decode_rsa_jwt(token text, keys jsonb)
    returns jsonb as
$$
declare
    -- ASN.1 headers for different SHA hash algorithms.
    sha_256_asn1           bytea := '\x3031300d060960864801650304020105000420';
    sha_384_asn1           bytea := '\x3041300d060960864801650304020205000430';
    sha_512_asn1           bytea := '\x3051300d060960864801650304020305000440';

    -- Variables to store JWT segments.
    segments               text[];
    header_segment         text;
    claims_segment         text;
    crypto_segment         text;
    message                text;
    signature              bytea;   -- Binary representation of the signature part of the JWT.
    signature_length       integer; -- Length of the signature segment in bytes.
    header                 jsonb;   -- JSONB decoded from the header segment.
    claims                 jsonb;   -- JSONB decoded from the claims segment.
    padding_length         integer; -- The length of the padding found in the decrypted signature.
    expected_signature     bytea;   -- The signature that is expected after correctly padding the decrypted message.
    decrypted_signature    bytea;   -- The clear text signature derived after decrypting.
    hash_asn1_header       bytea;   -- The ASN.1 header for the hash algorithm used for signing.
    hash_algorithm         text;    -- The hash algorithm used for signing.

    -- Variables to process each key for verification.
    keyrecord              jsonb;   -- Temporary storage for an individual key record.
    alg                    text;    -- Holds the algorithm used for signing.
    n                      numeric; -- The modulus in the RSA key.
    e                      integer; -- The exponent in the RSA key.
    keylength              integer; -- The length of the RSA key in bytes.
    cleartext              bytea;   -- Bytea representation of the decrypted signature.
    max_msglength          integer; -- Maximum allowable message length derived from the key length.
    msglength              integer; -- Actual length of the message being verified.
begin
    -- Split the token into its segments (header, claims, signature)
    segments := string_to_array(token, '.');

    if array_length(segments, 1) <> 3 then
        return null;
    end if;

    header_segment := segments[1];
    claims_segment := segments[2];
    crypto_segment := segments[3];
    message := header_segment || '.' || claims_segment;

    -- Check if any of the segments are null; if so, return null (indicating validation failure).
    if header_segment is null or claims_segment is null or crypto_segment is null then
        return null;
    end if;

    -- Decode the signature segment from the JWT.
    begin
        signature := urlsafe_b64decode(crypto_segment);
        signature_length := octet_length(signature);
    exception
        when others then
            return null;
    end;

    -- Attempt to decode and parse the header segment into JSONB; return null on failure.
    begin
        header := convert_from(urlsafe_b64decode(header_segment), 'UTF-8')::jsonb;
    exception
        when others then
            return null;
    end;

    -- Attempt to decode and parse the claims segment into JSONB; return null on failure.
    begin
        claims := convert_from(urlsafe_b64decode(claims_segment), 'UTF-8')::jsonb;
    exception
        when others then
            return null;
    end;

    -- Fetch algorithm from header and return null if it is not present.
    alg := header ->> 'alg';
    if alg is null then
        return null;
    end if;

    -- Select the appropriate ASN.1 header based on the algorithm.
    if alg = 'RS256' then
        hash_asn1_header := sha_256_asn1;
        hash_algorithm := 'sha256';
        keylength := 256;
    elsif alg = 'RS384' then
        hash_asn1_header := sha_384_asn1;
        hash_algorithm := 'sha384';
        keylength := 384;
    elsif alg = 'RS512' then
        hash_asn1_header := sha_512_asn1;
        hash_algorithm := 'sha512';
        keylength := 512;
    else
        -- If the algorithm is not supported, return null (indicating validation failure).
        return null;
    end if;

    -- Check if the crypto segment length matches the keylength
    if signature_length <> keylength then
        return null;
    end if;

    -- Construct the cleartext to be hashed and compared against the decrypted signature.
    cleartext := hash_asn1_header || digest(message, hash_algorithm);

    -- Calculate the padding and expected signature to validate against the decrypted signature.
    max_msglength := keylength - 11; -- PKCS#1 padding for RSA involves at least 11 bytes of overhead.

    -- Get the length of the hashed content.
    msglength := octet_length(cleartext);

    -- Calculate the padding length based on the key size and message length.
    padding_length := keylength - msglength - 3;

    -- Construct the expected_signature for comparison against the decrypted signature.
    expected_signature := '\x01'::bytea ||
                          ('\x' || repeat('ff', padding_length))::bytea ||
                          '\x00'::bytea ||
                          cleartext;

    -- Loop through each key provided and try to validate the JWT signature.
    for keyrecord in
        select jsonb_array_elements
        from jsonb_array_elements(keys)
        where  jsonb_array_elements ->> 'alg' = alg loop
        -- Extract the modulus and convert it to numeric.
        n := (keyrecord ->> 'n')::numeric;

        -- Extract the exponent and convert it to integer.
        e := (keyrecord ->> 'e')::int;

        -- Decrypt the signature using the key.
        decrypted_signature := decrypt_rsa(signature, e, n);

        -- Check if the decrypted signature contains the appropriate SHA ASN.1 header.
        if position(hash_asn1_header in decrypted_signature) = 0 then
            continue;
        end if;

        -- Check the signature validity
        if expected_signature is null or
           decrypted_signature is null or
           (expected_signature <> decrypted_signature) then
            continue;
        end if;

        -- The signature is valid, return the decoded JWT claims.
        return claims;
    end loop;

    -- If none of the keys matched, return null (indicating validation failure).
    return null;
end;
$$ language plpgsql immutable strict;
