# Usamos una versión ligera de Python
FROM python:3.10-slim

# Evita que Python genere archivos basura
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Carpeta de trabajo dentro de Docker
WORKDIR /app

# Instalamos dependencias del sistema para PostgreSQL
RUN apt-get update && apt-get install -y libpq-dev gcc

# Copiamos e instalamos los requerimientos
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos todo el código
COPY . .

# Exponemos el puerto de Flask
EXPOSE 5000

# Comando para arrancar
CMD ["python", "app.py"]