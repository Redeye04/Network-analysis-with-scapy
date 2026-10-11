FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    NETSCOPE_DATA_DIR=/data
WORKDIR /srv/netscope

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY tools ./tools
COPY run.py .

RUN useradd --create-home netscope && mkdir /data && chown netscope /data
USER netscope
VOLUME /data
EXPOSE 5000

# Analysis is CPU-bound and cached per worker; two workers suit small deployments.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "180", "app:create_app()"]
