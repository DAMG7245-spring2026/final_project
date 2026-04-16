# Airflow 2.8 + runtime deps for NVD three-stage DAGs (imports ingestion + app).
# Install as user `airflow` per https://airflow.apache.org/docs/docker-stack/build.html
FROM apache/airflow:2.8.3-python3.11

COPY --chown=airflow:root docker/airflow/requirements-dag-runtime.txt /requirements-dag-runtime.txt
RUN pip install --no-cache-dir -r /requirements-dag-runtime.txt
