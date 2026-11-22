FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
       python3 dpkg reprepro rsync openssh-client openssh-server openssl util-linux procps \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /run/sshd \
    && useradd --uid 65532 --no-create-home --home-dir /tmp/adapter-test --shell /bin/sh --password '*' adapter-test
WORKDIR /workspace
COPY . /workspace
ENV PYTHONDONTWRITEBYTECODE=1
USER 65532:65532
CMD ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"]
