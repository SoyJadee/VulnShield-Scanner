import os
from app import create_app


app = create_app()


if __name__ == '__main__':
    debug = os.getenv('FLASK_DEBUG', 'true').lower() in ('1', 'true', 'yes')
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', '5000'))
    app.run(debug=debug, host=host, port=port)
