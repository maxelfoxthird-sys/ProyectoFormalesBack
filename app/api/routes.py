"""
Módulo de rutas API para el análisis de JWT.

Define los endpoints REST para el análisis léxico, decodificación, sintactico, y semantico de JWT.
Se aplica como interfaz HTTP para el frontend y clientes externos.
"""

from flask import Blueprint, jsonify, request
from app.analyzer.lexical_analyzer import JWTLexer
from app.analyzer.decoder_json import get_decoded_strings
from app.analyzer.encoder import encode_jwt
from app.analyzer.crypto_verifier import verify_jwt_signature
from app.analyzer.semantic_analyzer import (
    SemanticAnalyzer,
    SemanticError,
    MissingClaimError,
    InvalidDataTypeError,
    InvalidValueError,
    ExpirationDateError,
    NotActiveTokenError
)
from app.analyzer.syntactic_analyzer import analyze_syntax
from app.services.database_service import DatabaseService


api_bp = Blueprint('api', __name__)
jwt_lexer = JWTLexer()
semantic_analyzer = SemanticAnalyzer()

@api_bp.route('/analyze/lexical/<string:jwt>', methods=['GET'])
def analyze_jwt(jwt):
    """
    Endpoint para análisis léxico de JWT.
    
    Recibe un JWT en la URL y retorna el resultado del análisis léxico (Fase 1).
    Se aplica como primer paso en el proceso de análisis de JWT.
    """
    try:
        result = jwt_lexer.analyze(jwt)
        return jsonify({
            'success': True,
            'result': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@api_bp.route('/analyze/decoder', methods=['POST'])
def analyze_jwt_decoder():
    """
    Endpoint para decodificación de JWT.
    
    Recibe el resultado del análisis léxico en el cuerpo (JSON) y retorna
    los strings JSON decodificados del header y payload. Se aplica después
    del análisis léxico (Fase 1) para obtener los JSON decodificados (Fase 4).
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No se recibió JSON en el cuerpo de la solicitud'
            }), 400
        
        if not isinstance(data, dict) or 'header' not in data or 'payload' not in data:
            return jsonify({
                'success': False,
                'error': 'El JSON debe contener el resultado del análisis léxico con "header" y "payload"'
            }), 400
        
        result = get_decoded_strings(data)
        
        return jsonify({
            'success': True,
            'result': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@api_bp.route('/analyze/semantic', methods=['POST'])
def analyze_jwt_semantic():
    """
    Endpoint para análisis semántico de JWT.
    
    Recibe header y payload como diccionarios y valida las reglas semánticas.
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No se recibió JSON en el cuerpo de la solicitud'
            }), 400
        
        if 'header' not in data or 'payload' not in data:
            return jsonify({
                'success': False,
                'error': 'El JSON debe contener "header" y "payload" como diccionarios'
            }), 400
        
        header_map = data['header']
        payload_map = data['payload']
        
        if not isinstance(header_map, dict) or not isinstance(payload_map, dict):
            return jsonify({
                'success': False,
                'error': 'Los campos "header" y "payload" deben ser diccionarios'
            }), 400
        
        # Realizar análisis semántico
        result = semantic_analyzer.analyze(header_map, payload_map)
        
        return jsonify({
            'success': True,
            'result': {
                'header': result[0],
                'payload': result[1],
                'valid': True
            }
        })
    except MissingClaimError as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': 'MissingClaimError'
        }), 400
    except InvalidDataTypeError as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': 'InvalidDataTypeError'
        }), 400
    except InvalidValueError as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': 'InvalidValueError'
        }), 400
    except ExpirationDateError as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': 'ExpirationDateError'
        }), 400
    except NotActiveTokenError as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': 'NotActiveTokenError'
        }), 400
    except SemanticError as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': 'SemanticError'
        }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@api_bp.route('/analyze/encoder', methods=['POST'])
def encode_jwt_endpoint():
    """
    Endpoint para codificación y firma de JWT.
    
    Recibe header y payload como objetos JSON y retorna el JWT completo
    codificado en Base64URL y firmado con el algoritmo especificado (HS256 o HS384).
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No se recibió JSON en el cuerpo de la solicitud'
            }), 400
        
        if 'header' not in data or 'payload' not in data:
            return jsonify({
                'success': False,
                'error': 'El JSON debe contener "header" y "payload" como objetos JSON'
            }), 400
        
        header = data['header']
        payload = data['payload']
        
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return jsonify({
                'success': False,
                'error': 'Los campos "header" y "payload" deben ser objetos JSON (diccionarios)'
            }), 400
        
        # Obtener la clave secreta (opcional, por defecto "secret")
        secret = data.get('secret', 'secret')
        
        if not isinstance(secret, str):
            return jsonify({
                'success': False,
                'error': 'El campo "secret" debe ser un string'
            }), 400
        
        # Codificar y firmar el JWT
        jwt_token = encode_jwt(header, payload, secret)
        
        return jsonify({
            'success': True,
            'jwt': jwt_token
        })
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@api_bp.route('/analyze/crypto-verification', methods=['POST'])
def verify_jwt_crypto():
    """
    Endpoint para verificación criptográfica de JWT.
    
    Recibe un JWT completo y una clave secreta. Recalcula la firma digital
    basándose en el contenido del header y payload y la compara con la firma
    adjunta en el token, validando así la integridad criptográfica.
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No se recibió JSON en el cuerpo de la solicitud'
            }), 400
        
        if 'jwt' not in data:
            return jsonify({
                'success': False,
                'error': 'El JSON debe contener el campo "jwt" con el token JWT completo'
            }), 400
        
        if 'secret' not in data:
            return jsonify({
                'success': False,
                'error': 'El JSON debe contener el campo "secret" con la clave secreta'
            }), 400
        
        jwt_token = data['jwt']
        secret = data['secret']
        
        if not isinstance(jwt_token, str):
            return jsonify({
                'success': False,
                'error': 'El campo "jwt" debe ser un string'
            }), 400
        
        if not isinstance(secret, str):
            return jsonify({
                'success': False,
                'error': 'El campo "secret" debe ser un string'
            }), 400
        
        # Verificar la firma criptográfica
        result = verify_jwt_signature(jwt_token, secret)
        
        if result['valid']:
            return jsonify({
                'success': True,
                'valid': True,
                'algorithm': result['algorithm'],
                'header': result['header'],
                'payload': result['payload']
            })
        else:
            return jsonify({
                'success': True,
                'valid': False,
                'error': result.get('error', 'Verificación fallida'),
                'algorithm': result.get('algorithm'),
                'header': result.get('header')
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@api_bp.route('/analyze/semantic_analyzer', methods=['POST'])

@api_bp.route('/analyze/syntax', methods=['POST'])
def syntax_analyzer_endpoint():
    """
    Endpoint para el análisis sintáctico del JWT.
    Recibe dos strings JSON provenientes del decoder.
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                'success': False,
                'error': 'No se recibió JSON en el cuerpo de la solicitud'
            }), 400

        # Se espera: { "result": ["json_header", "json_payload"] }
        if "result" not in data or not isinstance(data["result"], list) or len(data["result"]) != 2:
            return jsonify({
                'success': False,
                'error': 'Formato inválido. Se esperaba {"result": ["header", "payload"]}'
            }), 400

        header_str = data["result"][0]  # STRING JSON
        payload_str = data["result"][1] # STRING JSON

        # Llamar a tu analizador sintáctico
        result = analyze_syntax(header_str, payload_str)

        return jsonify({
            'success': True,
            'result': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/jwts', methods=['GET'])
def get_jwts():
    """
    Endpoint para obtener la lista de todos los JWTs de la base de datos.
    
    Retorna una lista de JWTs con su información completa.
    """
    try:
        jwts = DatabaseService.get_all_jwts()
        
        # Transformar los datos al formato esperado por el frontend
        formatted_jwts = []
        for jwt in jwts:
            # Obtener el secreto directamente
            secreto_valor = jwt.get('secreto')
            
            # Construir el diccionario asegurando que secreto siempre esté presente
            # Usar un valor por defecto si es None para evitar que Flask lo omita
            formatted_jwt = {
                'id': str(jwt.get('_id', '')),
                'token': str(jwt.get('token', '')),
                'name': str(jwt.get('name', f"JWT {str(jwt.get('_id', ''))[:8]}")),
                'createdAt': str(jwt.get('createdAt', jwt.get('_id', ''))),
                'valido': jwt.get('valido'),
                'secreto': str(secreto_valor) if secreto_valor is not None else '',  # Usar string vacío en lugar de None
            }
            
            # Agregar tipo_error si existe
            if 'tipo_error' in jwt:
                formatted_jwt['tipo_error'] = str(jwt['tipo_error'])
            else:
                formatted_jwt['tipo_error'] = None
            
            formatted_jwts.append(formatted_jwt)
        
        return jsonify({
            'success': True,
            'jwts': formatted_jwts
        })
    except Exception as e:
        # Log del error para debugging
        print(f"Error en get_jwts: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/health', methods=['GET'])
def health_check():
    """
    Endpoint de verificación de salud de la API.
    
    Retorna el estado de la API. Se aplica para monitoreo y verificación
    de que el servicio está en funcionamiento.
    """
    return jsonify({
        'status': 'healthy',
        'message': 'API is running'
    })
