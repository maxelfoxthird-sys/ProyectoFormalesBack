"""
Servicio de base de datos para operaciones con JWTs.

Proporciona métodos para interactuar con la colección JWTS en MongoDB.
"""

import sys
import os

# Agregar el directorio data al path para importar crud
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
data_dir = os.path.join(backend_dir, 'data')
if data_dir not in sys.path:
    sys.path.insert(0, data_dir)

from crud import obtener_todos, obtener_por_id, insertar_uno, actualizar_por_id, eliminar_por_id


class DatabaseService:
    """Servicio para operaciones de base de datos con JWTs."""
    
    COLLECTION_NAME = "JWTS"
    
    @staticmethod
    def get_all_jwts():
        """
        Obtiene todos los JWTs de la base de datos.
        
        Returns:
            list: Lista de documentos JWT con _id convertido a string
        """
        try:
            jwts = obtener_todos(DatabaseService.COLLECTION_NAME)
            return jwts
        except Exception as e:
            raise Exception(f"Error al obtener JWTs de la base de datos: {str(e)}")
    
    @staticmethod
    def get_jwt_by_id(jwt_id):
        """
        Obtiene un JWT por su ID.
        
        Args:
            jwt_id: ID del JWT a obtener
            
        Returns:
            dict: Documento JWT o None si no existe
        """
        try:
            jwt = obtener_por_id(DatabaseService.COLLECTION_NAME, jwt_id)
            return jwt
        except Exception as e:
            raise Exception(f"Error al obtener JWT por ID: {str(e)}")
    
    @staticmethod
    def create_jwt(jwt_data):
        """
        Crea un nuevo JWT en la base de datos.
        
        Args:
            jwt_data: Diccionario con los datos del JWT (debe incluir 'token')
            
        Returns:
            str: ID del JWT creado
        """
        try:
            jwt_id = insertar_uno(DatabaseService.COLLECTION_NAME, jwt_data)
            return jwt_id
        except Exception as e:
            raise Exception(f"Error al crear JWT: {str(e)}")
    
    @staticmethod
    def update_jwt(jwt_id, update_data):
        """
        Actualiza un JWT existente.
        
        Args:
            jwt_id: ID del JWT a actualizar
            update_data: Diccionario con los campos a actualizar
            
        Returns:
            bool: True si la actualización fue exitosa
        """
        try:
            return actualizar_por_id(DatabaseService.COLLECTION_NAME, jwt_id, update_data)
        except Exception as e:
            raise Exception(f"Error al actualizar JWT: {str(e)}")
    
    @staticmethod
    def delete_jwt(jwt_id):
        """
        Elimina un JWT de la base de datos.
        
        Args:
            jwt_id: ID del JWT a eliminar
            
        Returns:
            bool: True si la eliminación fue exitosa
        """
        try:
            return eliminar_por_id(DatabaseService.COLLECTION_NAME, jwt_id)
        except Exception as e:
            raise Exception(f"Error al eliminar JWT: {str(e)}")

