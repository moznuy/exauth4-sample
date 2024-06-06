FROM python:3.11-alpine as base

FROM base as requirements-stage

WORKDIR /tmp

RUN pip install poetry
COPY ./pyproject.toml ./poetry.lock* /tmp/

RUN poetry export -f requirements.txt --output requirements.txt --without-hashes

FROM base as runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=requirements-stage /tmp/requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt && rm -rf /root/.cache

WORKDIR /app
COPY exauth /app/exauth

EXPOSE 80

CMD ["gunicorn", "--bind", "0.0.0.0:80", "-k", "gevent", "--worker-connections", "1000", "exauth:app"]
