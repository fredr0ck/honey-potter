FROM node:20-alpine

WORKDIR /app

# Копирование package files
COPY package*.json ./

# Установка зависимостей
RUN npm install

# Копирование кода
COPY . .

# Expose port
EXPOSE 3000

# Команда запуска
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

