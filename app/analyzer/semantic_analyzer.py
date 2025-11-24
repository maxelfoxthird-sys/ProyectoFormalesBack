import time 

class SemanticError(ValueError):
    """Clase base para todos los errores semánticos."""
    pass

class MissingClaimError(SemanticError):
    """(Reglas R-H1, R-H4)"""
    pass

class InvalidDataTypeError(SemanticError):
    """(Reglas R-H2, R-H5, R-P1, R-P3, R-P5, R-P6, R-P7)"""
    pass

class InvalidValueError(SemanticError):
    """(Reglas R-H3, R-H6)"""
    pass

class ExpirationDateError(SemanticError):
    """(Regla R-P2)"""
    pass

class NotActiveTokenError(SemanticError):
    """(Regla R-P4)"""
    pass

class SemanticAnalyzer:
    def __init__(self):
        self.supported_algorithms = {"HS256", "HS384"}

    def analyze(self, header_map, payload_map):
        t_actual = int(time.time())
        self._validate_header(header_map)
        self._validate_payload(payload_map, t_actual)

        return (header_map, payload_map)

    def _validate_header(self, h_map):

        if 'alg' not in h_map:
            raise MissingClaimError("ERROR_CLAIM_FALTANTE: El claim 'alg' es obligatorio.")
        
        if 'typ' not in h_map:
            raise MissingClaimError("ERROR_CLAIM_FALTANTE: El claim 'typ' es obligatorio.")

        if not isinstance(h_map['alg'], str):
            raise InvalidDataTypeError("ERROR_TIPO_DATO_INVALIDO: El claim 'alg' debe ser un String.")

        if not isinstance(h_map['typ'], str):
            raise InvalidDataTypeError("ERROR_TIPO_DATO_INVALIDO: El claim 'typ' debe ser un String.")

        if h_map['alg'] not in self.supported_algorithms:
            raise InvalidValueError(f"ERROR_VALOR_INVALIDO: El alg '{h_map['alg']}' no es soportado.")

        if h_map['typ'] != "JWT":
            raise InvalidValueError("ERROR_VALOR_INVALIDO: El claim 'typ' debe ser 'JWT'.")

    def _validate_payload(self, p_map, t_actual):

        if 'exp' in p_map:
            if not isinstance(p_map['exp'], int):
                raise InvalidDataTypeError("ERROR_TIPO_DATO_INVALIDO: 'exp' debe ser NumericDate (int).")
            if t_actual >= p_map['exp']:
                raise ExpirationDateError(f"ERROR_TOKEN_EXPIRADO: El token expiró.")

        if 'nbf' in p_map:
            if not isinstance(p_map['nbf'], int):
                raise InvalidDataTypeError("ERROR_TIPO_DATO_INVALIDO: 'nbf' debe ser NumericDate (int).")
            if t_actual < p_map['nbf']:
                raise NotActiveTokenError("ERROR_TOKEN_NO_ACTIVO: El token aún no es válido.")

        if 'iat' in p_map and not isinstance(p_map['iat'], int):
            raise InvalidDataTypeError("ERROR_TIPO_DATO_INVALIDO: 'iat' debe ser NumericDate (int).")

        if 'iss' in p_map and not isinstance(p_map['iss'], str):
            raise InvalidDataTypeError("ERROR_TIPO_DATO_INVALIDO: 'iss' debe ser String.")

        if 'sub' in p_map and not isinstance(p_map['sub'], str):
            raise InvalidDataTypeError("ERROR_TIPO_DATO_INVALIDO: 'sub' debe ser String.")

        if 'aud' in p_map:
            aud = p_map['aud']
            es_string = isinstance(aud, str)
            es_list = isinstance(aud, list) and all(isinstance(s, str) for s in aud)

            if not (es_string or es_list):
                raise InvalidDataTypeError("ERROR_TIPO_DATO_INVALIDO: 'aud' debe ser String o Arreglo de Strings.")