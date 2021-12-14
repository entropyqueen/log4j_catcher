FROM python:3.9-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y protobuf-compiler gcc git && \
    rm -rf /var/lib/apt/lists/*

COPY log4j_exploit.yara .
COPY detector.py .
COPY requirements.txt .

RUN python3 -m pip install -r requirements.txt
RUN rm -rf requirements.txt

ENV PORT=8080
CMD "python3" "/app/detector.py" $PORT
