import os
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
from app.api.routes import api_bp

# Cargar variables de entorno desde .env
load_dotenv()

def create_app():
    """Factory function to create Flask app instance"""
    app = Flask(__name__)
    
    # Configuration desde variables de entorno
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'amarillo-platano')
    app.config['DEBUG'] = os.getenv('DEBUG', 'False').lower() in ('true', '1', 'yes')
    
    # Configurar CORS para permitir cualquier origen
    CORS(app)
    
    # Register blueprints
    app.register_blueprint(api_bp, url_prefix='/api')
    
    return app

if __name__ == '__main__':
    app = create_app()
    
    # Obtener configuración del servidor desde variables de entorno
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() in ('true', '1', 'yes')
    
    app.run(host=host, port=port, debug=debug)
