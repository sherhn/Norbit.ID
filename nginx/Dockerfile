# Используем легкий официальный образ Nginx
FROM nginx:alpine

# Удаляем стандартную конфигурацию Nginx
RUN rm /etc/nginx/conf.d/default.conf

# Копируем наш файл конфигурации
COPY nginx.conf /etc/nginx/conf.d/default.conf