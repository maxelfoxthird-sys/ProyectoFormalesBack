# -*- coding: utf-8 -*-
"""
TEST DEL ANALIZADOR SEMÁNTICO (PROYECTO JWT)
--------------------------------------------
Archivo temporal para probar el analizador semántico.
"""

import time

try:
    from app.analyzer.semantic_analyzer import (
        SemanticAnalyzer,
        MissingClaimError,
        InvalidDataTypeError,
        InvalidValueError,
        ExpirationDateError,
        NotActiveTokenError
    )
except ModuleNotFoundError:
    # When this file is run directly from the repository root (or other CWD),
    # the package `app` may not be on sys.path. Add the `backend` folder
    # dynamically so the absolute import works.
    import os
    import sys

    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

    from app.analyzer.semantic_analyzer import (
        SemanticAnalyzer,
        MissingClaimError,
        InvalidDataTypeError,
        InvalidValueError,
        ExpirationDateError,
        NotActiveTokenError
    )

# Obtener tiempo actual para casos de prueba con fechas válidas
t_actual = int(time.time())
t_futuro = t_actual + 3600  # 1 hora en el futuro
t_pasado = t_actual - 3600  # 1 hora en el pasado

# ------------------------------
# CASOS VÁLIDOS
# ------------------------------

valid_cases = {
    "case1_basic": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"sub": "foo", "name": "John Doe"},
        "expected_valid": True
    },
    "case2_full_claims": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {
            "iss": "https://api.mi-proyecto.com",
            "sub": "auth0|1234567890",
            "aud": "https://api.mi-proyecto.com/v1",
            "iat": t_pasado,
            "exp": t_futuro,
            "nbf": t_pasado,
            "jti": "abc-def-123",
            "username": "jose.salamanca",
            "role": "admin"
        },
        "expected_valid": True
    },
    "case3_hs384": {
        "header": {"alg": "HS384", "typ": "JWT"},
        "payload": {
            "iss": "https://auth.mi-proyecto.com",
            "sub": "google-oauth2|1122334455",
            "aud": ["https://api.mi-proyecto.com/v1", "https://admin.mi-proyecto.com"],
            "iat": t_pasado,
            "exp": t_futuro,
            "jti": "mno-pqr-789",
            "email": "test@gmail.com",
            "permissions": ["read:data", "write:data"]
        },
        "expected_valid": True
    },
    "case4_minimal_payload": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {},
        "expected_valid": True
    },
    "case5_only_exp": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"exp": t_futuro, "sub": "user123"},
        "expected_valid": True
    },
    "case6_only_nbf": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"nbf": t_pasado, "sub": "user123"},
        "expected_valid": True
    },
    "case7_aud_string": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"aud": "https://api.example.com", "sub": "user123"},
        "expected_valid": True
    },
    "case8_aud_array": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"aud": ["https://api.example.com", "https://admin.example.com"], "sub": "user123"},
        "expected_valid": True
    },
}

# ------------------------------
# CASOS INVÁLIDOS - HEADER
# ------------------------------

invalid_cases_header = {
    "missing_alg": {
        "header": {"typ": "JWT"},
        "payload": {"sub": "foo"},
        "expected_error": MissingClaimError,
        "description": "R-H1: Falta 'alg' en header"
    },
    "missing_typ": {
        "header": {"alg": "HS256"},
        "payload": {"sub": "foo"},
        "expected_error": MissingClaimError,
        "description": "R-H4: Falta 'typ' en header"
    },
    "alg_not_string": {
        "header": {"alg": 123, "typ": "JWT"},
        "payload": {"sub": "foo"},
        "expected_error": InvalidDataTypeError,
        "description": "R-H2: 'alg' no es String"
    },
    "typ_not_string": {
        "header": {"alg": "HS256", "typ": 456},
        "payload": {"sub": "foo"},
        "expected_error": InvalidDataTypeError,
        "description": "R-H5: 'typ' no es String"
    },
    "alg_not_supported": {
        "header": {"alg": "RS256", "typ": "JWT"},
        "payload": {"sub": "foo"},
        "expected_error": InvalidValueError,
        "description": "R-H3: 'alg' no es HS256 ni HS384"
    },
    "typ_not_jwt": {
        "header": {"alg": "HS256", "typ": "JWP"},
        "payload": {"sub": "foo"},
        "expected_error": InvalidValueError,
        "description": "R-H6: 'typ' no es 'JWT'"
    },
}

# ------------------------------
# CASOS INVÁLIDOS - PAYLOAD
# ------------------------------

invalid_cases_payload = {
    "exp_not_int": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"exp": "not_a_number", "sub": "foo"},
        "expected_error": InvalidDataTypeError,
        "description": "R-P2: 'exp' no es NumericDate (int)"
    },
    "exp_expired": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"exp": t_pasado, "sub": "foo"},
        "expected_error": ExpirationDateError,
        "description": "R-P2: Token expirado (exp < t_actual)"
    },
    "nbf_not_int": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"nbf": "not_a_number", "sub": "foo"},
        "expected_error": InvalidDataTypeError,
        "description": "R-P3: 'nbf' no es NumericDate (int)"
    },
    "nbf_not_active": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"nbf": t_futuro, "sub": "foo"},
        "expected_error": NotActiveTokenError,
        "description": "R-P4: Token aún no activo (nbf > t_actual)"
    },
    "iat_not_int": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"iat": "not_a_number", "sub": "foo"},
        "expected_error": InvalidDataTypeError,
        "description": "R-P1: 'iat' no es NumericDate (int)"
    },
    "iss_not_string": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"iss": 123, "sub": "foo"},
        "expected_error": InvalidDataTypeError,
        "description": "R-P5: 'iss' no es String"
    },
    "sub_not_string": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"sub": 456, "iss": "https://example.com"},
        "expected_error": InvalidDataTypeError,
        "description": "R-P6: 'sub' no es String"
    },
    "aud_not_string_or_array": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"aud": 789, "sub": "foo"},
        "expected_error": InvalidDataTypeError,
        "description": "R-P7: 'aud' no es String ni Arreglo de Strings"
    },
    "aud_array_with_non_strings": {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {"aud": ["https://api.example.com", 123, "https://admin.example.com"], "sub": "foo"},
        "expected_error": InvalidDataTypeError,
        "description": "R-P7: 'aud' es array pero contiene elementos no-string"
    },
}

# ------------------------------
# EJECUCIÓN DE PRUEBAS
# ------------------------------

analyzer = SemanticAnalyzer()

def print_result(name, header, payload, result, expected_valid=None, expected_error=None, description=""):
    print("\n========== RESULTADO:", name, "==========")
    if description:
        print("Descripcion:", description)
    print("Header:", header)
    print("Payload:", payload)
    
    if isinstance(result, tuple):
        # Caso válido
        print("[OK] Validacion exitosa")
        print("Header resultante:", result[0])
        print("Payload resultante:", result[1])
        if expected_valid is not None:
            if expected_valid:
                print("[OK] Resultado coincide con lo esperado (valido)")
            else:
                print("[ERROR] Se esperaba invalido pero paso la validacion!")
    else:
        # Caso con error
        error_type = type(result).__name__
        error_msg = str(result)
        print("[ERROR]", error_type + ":", error_msg)
        if expected_error:
            if isinstance(result, expected_error):
                print("[OK] Tipo de error coincide con lo esperado:", expected_error.__name__)
            else:
                print("[ERROR] Tipo de error NO coincide! Esperado:", expected_error.__name__, "Obtenido:", error_type)

print("\n=====================")
print("PRUEBAS CON CASOS VÁLIDOS (SE ESPERA QUE PASEN)")
print("=====================")

for name, case in valid_cases.items():
    try:
        result = analyzer.analyze(case["header"], case["payload"])
        print_result(name, case["header"], case["payload"], result, expected_valid=True)
    except Exception as e:
        print_result(name, case["header"], case["payload"], e, expected_valid=True, description="[ERROR INESPERADO]")

print("\n=====================")
print("PRUEBAS CON ERRORES EN HEADER (SE ESPERA QUE FALLEN)")
print("=====================")

for name, case in invalid_cases_header.items():
    try:
        result = analyzer.analyze(case["header"], case["payload"])
        print_result(name, case["header"], case["payload"], result, expected_error=case["expected_error"], description=case["description"])
        print("[ERROR] Se esperaba error pero paso la validacion!")
    except Exception as e:
        print_result(name, case["header"], case["payload"], e, expected_error=case["expected_error"], description=case["description"])

print("\n=====================")
print("PRUEBAS CON ERRORES EN PAYLOAD (SE ESPERA QUE FALLEN)")
print("=====================")

for name, case in invalid_cases_payload.items():
    try:
        result = analyzer.analyze(case["header"], case["payload"])
        print_result(name, case["header"], case["payload"], result, expected_error=case["expected_error"], description=case["description"])
        print("[ERROR] Se esperaba error pero paso la validacion!")
    except Exception as e:
        print_result(name, case["header"], case["payload"], e, expected_error=case["expected_error"], description=case["description"])

print("\n=====================")
print("PRUEBAS COMPLETADAS")
print("=====================")

