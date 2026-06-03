# Ubuntu endpoint monitored by Wazuh.
# Installs the Wazuh agent from the official APT repo. WAZUH_MANAGER is baked at
# install time so ossec.conf points at the manager; the entrypoint enrolls and
# starts the agent, then generates light activity for FIM/log alerts.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    WAZUH_MANAGER=wazuh-manager \
    WAZUH_AGENT_NAME=ubuntu-endpoint

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl gnupg2 lsb-release ca-certificates procps && \
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y wazuh-agent=4.9.2-1 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
