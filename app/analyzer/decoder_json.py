"""
Módulo de decodificación JSON para JWT.

Decodifica tokens Base64URL de header y payload a strings JSON.
Se aplica después del análisis léxico (Fase 1) y antes del análisis sintáctico (Fase 2).
"""

import base64
from typing import Dict, List, Any


def decode_base64url(encoded_string: str) -> str:
    """
    Decodifica un string Base64URL a UTF-8.
    
    Se aplica para convertir tokens Base64URL del JWT a strings JSON legibles.
    """
    base64_string = encoded_string.replace('-', '+').replace('_', '/')
    
    padding_length = 4 - (len(base64_string) % 4)
    if padding_length != 4:
        base64_string += '=' * padding_length
    
    try:
        decoded_bytes = base64.urlsafe_b64decode(base64_string)
        return decoded_bytes.decode('utf-8')
    except (base64.binascii.Error, UnicodeDecodeError) as e:
        raise ValueError(f"Error de decodificación Base64URL: {e}")


def get_decoded_strings(lex_result: Dict[str, Any]) -> List[str]:
    """
    Decodifica header y payload de Base64URL a JSON.
    
    Recibe el resultado del análisis léxico (con 'valid', 'header', 'payload')
    y retorna una lista [header_json, payload_json] para el análisis sintáctico.
    """
    if not isinstance(lex_result, dict):
        raise ValueError("Error Léxico: La entrada debe ser un diccionario.")
    
    if not lex_result.get('valid', False):
        raise ValueError("Error Léxico: El JWT no es válido según el análisis léxico.")
    
    if 'header' not in lex_result or 'payload' not in lex_result:
        raise ValueError(
            "Error Léxico: La entrada del lexer no es válida o está incompleta. "
            "Se requieren los campos 'header' y 'payload'."
        )
    
    try:
        header_b64 = lex_result['header']
        payload_b64 = lex_result['payload']
        
        decoded_header = decode_base64url(header_b64)
        decoded_payload = decode_base64url(payload_b64)
        
        return [decoded_header, decoded_payload]
        
    except ValueError as e:
        raise ValueError(f"Error en la Fase 4 (Decodificación): {e}") from e