# -----------------------------------------------------------------------------
# Dockerfile security review for Exercise 2.
#
# The exercise asks only to identify issues with the Dockerfile.
# Therefore, this file keeps the original Dockerfile structure as commented
# evidence and adds security review comments above each risky pattern.
# -----------------------------------------------------------------------------

FROM UBUNTU:18.04
# ISSUE:
# ubuntu:18.04 is an old and broad operating system base image.
# It increases the attack surface and may contain outdated packages.
#
# RECOMMENDATION:
# Use a maintained, minimal, application-specific base image such as a current
# python slim image.

USER root
# ISSUE:
# The application runs as root.
# If the container is compromised, the attacker has higher privileges inside
# the container.
#
# RECOMMENDATION:
# Create and run as a dedicated non-root application user.

RUN apt-get update && apt-get install -y \
 python3 \
 python3-pip \
 curl \
 vim \
 dnsutils
# ISSUE:
# The image installs unnecessary troubleshooting tools such as curl, vim,
# and dnsutils. These increase image size and attacker utility after compromise.
# There is also no package version pinning and no apt cache cleanup.
#
# RECOMMENDATION:
# Install only runtime dependencies required by the application.
# Use pinned dependencies where practical and clean package manager cache.

ENV DB_PASSWORD="SuperSecretPassword123!"
ENV API_KEY="prod-key-778899"
# ISSUE:
# Secrets are hardcoded into the Docker image.
# Dockerfile ENV values can be exposed through image history, registry metadata,
# local inspection, CI logs, or compromised developer environments.
#
# RECOMMENDATION:
# Do not put secrets into images. Insert them at runtime using a secret manager
# or orchestrator-level secret mechanism.

COPY . /app
# ISSUE:
# Copies the entire build context into the image.
# This may include .git, .env files, credentials, Terraform variables, tests,
# local configuration, or other unnecessary/sensitive files.
#
# RECOMMENDATION:
# Use a .dockerignore file and copy only the files required at runtime.

RUN chmod -R 777 /app
# ISSUE:
# Grants read, write, and execute permissions to everyone.
# A compromised process or unexpected user could modify application files.
#
# RECOMMENDATION:
# Use least-privilege filesystem permissions, assign ownership to the application
# user, and avoid granting write permissions to all users.

EXPOSE 80
# ISSUE:
# Port 80 is a privileged low port in Linux environments and often implies root
# execution or additional capabilities.
#
# RECOMMENDATION:
# Run the app on a high unprivileged port such as 8080 and let the platform or
# load balancer map external traffic.

WORKDIR /app
# ISSUE:
# WORKDIR itself is not a security issue.
# However, combined with COPY . /app and chmod -R 777 /app, the application
# directory becomes overly permissive and may contain unnecessary files.
#
# RECOMMENDATION:
# Keep WORKDIR, but pair it with controlled copy behavior and restrictive
# permissions.

CMD python3 app.py
# ISSUE:
# Shell-form CMD has weaker signal-handling behavior.
#
# RECOMMENDATION:
# Use exec-form CMD, for example:
# CMD ["python3", "app.py"]
