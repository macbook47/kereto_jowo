FROM python:3.9.8

RUN mkdir -p /app /data
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT [ "python", "kereto_jowo.py" ]
