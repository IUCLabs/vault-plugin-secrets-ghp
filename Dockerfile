FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/vault-plugin-secrets-ghp /vault-plugin-secrets-ghp
ENTRYPOINT ["/vault-plugin-secrets-ghp"]
