"""
Módulo de verificación criptográfica para JWT.

Verifica la integridad criptográfica de un JWT recalculando la firma
y comparándola con la firma adjunta en el token.
"""

import json
import base64
import hmac
import hashlib
from typing import Dict, Any


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


def sign_token(header_b64: str, payload_b64: str, algorithm: str, secret: str) -> str:
    """
    Firma un token JWT usando HMAC con el algoritmo especificado.
    
    Recibe header y payload codificados en Base64URL, el algoritmo (HS256 o HS384)
    y la clave secreta. Retorna la firma codificada en Base64URL.
    """
    message = f"{header_b64}.{payload_b64}"
    
    if algorithm == "HS256":
        hash_algorithm = hashlib.sha256
    elif algorithm == "HS384":
        hash_algorithm = hashlib.sha384
    else:
        raise ValueError(f"Algoritmo no soportado: {algorithm}. Solo se soportan HS256 y HS384.")
    
    signature_bytes = hmac.new(
        secret.encode('utf-8'),
        message.encode('utf-8'),
        hash_algorithm
    ).digest()
    
    signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode('utf-8')
    return signature_b64.rstrip('=')


def verify_jwt_signature(jwt_token: str, secret: str) -> Dict[str, Any]:
    """
    Verifica la integridad criptográfica de un JWT.
    
    Recalcula la firma digital basándose en el contenido del header y payload
    y la compara con la firma adjunta en el token.
    
    Args:
        jwt_token: String con el JWT completo en formato header.payload.signature
        secret: Clave secreta para recalcular la firma
    
    Returns:
        Diccionario con:
            - valid: bool indicando si la verificación fue exitosa
            - algorithm: algoritmo usado (HS256 o HS384)
            - header: diccionario con el header decodificado
            - payload: diccionario con el payload decodificado
            - error: mensaje de error si la verificación falló
    """
    try:
        # Separar el JWT en sus componentes
        parts = jwt_token.split('.')
        
        if len(parts) != 3:
            return {
                'valid': False,
                'error': 'Formato de JWT inválido: debe tener 3 partes separadas por puntos'
            }
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Decodificar el header para obtener el algoritmo
        try:
            header_json = decode_base64url(header_b64)
            header = json.loads(header_json)
        except (ValueError, json.JSONDecodeError) as e:
            return {
                'valid': False,
                'error': f'Error al decodificar el header: {e}'
            }
        
        # Validar que el header tenga el algoritmo
        if 'alg' not in header:
            return {
                'valid': False,
                'error': 'El header no contiene el claim "alg"'
            }
        
        algorithm = header['alg']
        
        if algorithm not in ["HS256", "HS384"]:
            return {
                'valid': False,
                'error': f'Algoritmo no soportado: {algorithm}. Solo se soportan HS256 y HS384.'
            }
        
        # Recalcular la firma
        try:
            recalculated_signature = sign_token(header_b64, payload_b64, algorithm, secret)
        except ValueError as e:
            return {
                'valid': False,
                'error': str(e)
            }
        
        # Comparar firmas usando comparación segura (evita timing attacks)
        # Normalizar las firmas removiendo padding si es necesario
        signature_normalized = signature_b64.rstrip('=')
        recalculated_normalized = recalculated_signature.rstrip('=')
        
        # Usar comparación segura de strings
        if not hmac.compare_digest(signature_normalized, recalculated_normalized):
            return {
                'valid': False,
                'algorithm': algorithm,
                'header': header,
                'error': 'La firma no coincide. El token puede haber sido alterado o la clave secreta es incorrecta.'
            }
        
        # Decodificar el payload para incluirlo en la respuesta
        try:
            payload_json = decode_base64url(payload_b64)
            payload = json.loads(payload_json)
        except (ValueError, json.JSONDecodeError) as e:
            return {
                'valid': False,
                'error': f'Error al decodificar el payload: {e}'
            }
        
        return {
            'valid': True,
            'algorithm': algorithm,
            'header': header,
            'payload': payload
        }
        
    except Exception as e:
        return {
            'valid': False,
            'error': f'Error inesperado durante la verificación: {e}'
        }

