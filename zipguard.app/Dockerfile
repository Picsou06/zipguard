FROM python:3.13-slim AS base

LABEL org.opencontainers.image.title="ZipGuard" \
	org.opencontainers.image.description="Boîte à outils éducative et défensive contre les bombes de décompression." \
	org.opencontainers.image.source="https://github.com/Picsou06/zipguard" \
	org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1 \
	PIP_NO_CACHE_DIR=1 \
	PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src

RUN pip install --no-cache-dir . \
	&& useradd --create-home --uid 10001 guard \
	&& mkdir -p /samples \
	&& chown guard:guard /samples

USER guard

# Le conteneur ne sert qu'à inspecter des archives montées en lecture : il n'a besoin ni de
# privilèges, ni d'écrire ailleurs que dans le dossier de sortie qu'on lui donne.
ENTRYPOINT ["zipguard"]
CMD ["--help"]
