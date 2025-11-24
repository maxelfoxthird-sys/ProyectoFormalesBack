from pymongo import MongoClient
import os

# Cargar conexión desde variables de entorno
#MONGO_URI = os.getenv("MONGO_URI")

MONGO_URI = "mongodb+srv://sam:sam12@jwtdata.skndjwz.mongodb.net/?appName=JWTData"


client = MongoClient(MONGO_URI)

# Nombre de tu base de datos
db = client["JWTData"]

print("Conexión exitosa a MongoDB Atlas")
