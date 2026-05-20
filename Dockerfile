FROM ubuntu:22.04

# Install all tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    whatweb \
    theharvester \
    dnstwist \
    git \
    python3-pip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install metagoofil
RUN git clone https://github.com/laramies/metagoofil.git /opt/metagoofil

# Install sherlock
RUN git clone https://github.com/sherlock-project/sherlock.git /opt/sherlock && \
    cd /opt/sherlock && pip3 install -r requirements.txt --break-system-packages

# Install spiderfoot
RUN apt-get update && apt-get install -y spiderfoot

# Install python-telegram-bot
RUN pip3 install python-telegram-bot --break-system-packages

# Copy the bot script
COPY phantomwatch.py /app/phantomwatch.py

WORKDIR /app

CMD ["python3", "phantomwatch.py"]
