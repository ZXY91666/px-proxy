FROM python:3.12-slim

# cache bust — 每次改动这行都会强制重建
ARG CACHEBUST=20261114_0941
RUN echo "build $CACHEBUST"

WORKDIR /app
COPY app.py .

ENV PYTHONUNBUFFERED=1
ENV PORT=8080

EXPOSE 8080
EXPOSE 8081
EXPOSE 8082

CMD ["python", "app.py"]
