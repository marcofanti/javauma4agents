# Builds the upstream AAuth Person Server / Agent Server unified portal from
# the pinned checkout in aauth/upstream/ (see make fetch-upstream).
#
# Dependencies come from the pinned source's own uv.lock, with hashes, rather
# than from pyproject.toml's ranges. Its lock holds aauth-signing at 0.1.2; an
# unconstrained `pip install -e .` resolves aauth-signing 0.2.0, whose
# fully-specified-algorithm check makes enrollment fail with a 500.

FROM python:3.12.12-slim AS lock
RUN pip install --no-cache-dir 'uv==0.9.5'
WORKDIR /src
COPY upstream/aauth-person-server/pyproject.toml upstream/aauth-person-server/uv.lock ./
RUN uv export --frozen --no-dev --no-emit-project --format requirements-txt \
        -o /requirements.txt

FROM python:3.12.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=lock /requirements.txt /requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /requirements.txt
COPY upstream/aauth-person-server/ .
RUN pip install --no-cache-dir --no-deps -e .
EXPOSE 8765
CMD ["uvicorn", "portal.http.app:app", "--host", "0.0.0.0", "--port", "8765"]
