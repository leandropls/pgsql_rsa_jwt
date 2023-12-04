select jwt.decode_jwt(
    token := :token,
    keys := jsonb_build_array(
       jwt.jwk_to_key(:jwk)
    )
) as decode_failure_jwt_hmac
