# Escolher a imagem base do Python
FROM python:3.11-slim

# Definir diretório de trabalho dentro do contêiner
WORKDIR /app

# Copiar dependências
COPY requirements.txt .

# Instalar dependências
RUN pip install --no-cache-dir -r requirements.txt

# Copiar o código do projeto
COPY . .

# Expôr a porta que o Flask vai usar
EXPOSE 3030

# Comando para rodar o Flask
CMD ["python", "main.py"]
