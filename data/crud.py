"""
crud.py
-------
Este módulo contiene todas las operaciones  basicas para MongoDB Atlas.


- Insertar 
- Obtener listas completas
- Consultar por ID
- Modificar datos
- Eliminar datos

IMPORTANTE:
asegurar la variarble mogo uri, para el caso esta con mis datos de sam sam12 
este es un ejemplo de como se ve la uri.

    MONGO_URI="mongodb+srv://<usuario>:<password>@<cluster>.mongodb.net/"

coleccion : es el nombre de la base de datos que se va a usar en MONGO ATLAS
documento: son los datos a insertar/modifcar o elimnar
"""

from bson.objectid import ObjectId
from db import db


# ===========================
# 1. CREATE (INSERTAR DATOS)
# ===========================

def insertar_uno(coleccion, documento):
    """
    Inserta un solo documento en una colección.
    Regresa el ID generado.
    """
    resultado = db[coleccion].insert_one(documento)
    return str(resultado.inserted_id)


def insertar_varios(coleccion, lista_documentos):
    """
    Inserta varios documentos en una colección.
    """
    resultado = db[coleccion].insert_many(lista_documentos)
    return [str(_id) for _id in resultado.inserted_ids]


# ===========================
# 2. READ (LEER DATOS)
# ===========================

def obtener_todos(coleccion):
    """
    Obtiene todos los documentos de una colección.
    Convierte ObjectId a string para evitar errores en el front.
    """
    documentos = list(db[coleccion].find({}))
    for d in documentos:
        d["_id"] = str(d["_id"])
    return documentos


def obtener_por_id(coleccion, id_documento):
    """
    Obtiene un documento por su ID.
    """
    documento = db[coleccion].find_one({"_id": ObjectId(id_documento)})
    if documento:
        documento["_id"] = str(documento["_id"])
    return documento


# ===========================
# 3. UPDATE (MODIFICAR DATOS)
# ===========================

def actualizar_por_id(coleccion, id_documento, nuevos_datos):
    """
    Actualiza un documento por ID.
    nuevos_datos debe ser un diccionario con los campos a modificar.
    """
    db[coleccion].update_one(
        {"_id": ObjectId(id_documento)},
        {"$set": nuevos_datos}
    )
    return True


# ===========================
# 4. DELETE (ELIMINAR DATOS)
# ===========================

def eliminar_por_id(coleccion, id_documento):
    """
    Elimina un documento por ID.
    """
    db[coleccion].delete_one({"_id": ObjectId(id_documento)})
    return True


def eliminar_todos(coleccion):
    """
    Elimina todos los documentos de una colección.
    Úsalo con cuidado.
    """
    db[coleccion].delete_many({})
    return True

