FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends build-essential

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./ /code

ENV PYTHONPATH "${PYTHONPATH}:/code:/code/app"

# DEVELOPMENT
CMD ["fastapi", "dev", "server/main.py", "--port", "8080", "--host", "0.0.0.0"]