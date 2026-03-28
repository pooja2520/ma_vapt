FROM python:3.11-slim
 
WORKDIR /app
 
# Install base tools
RUN apt-get update && apt-get install -y \
    nmap \
    masscan \
    golang \
    git \
    curl \
    perl \
    make \
&& rm -rf /var/lib/apt/lists/*
 
# Install Nikto manually
RUN git clone https://github.com/sullo/nikto.git /opt/nikto
ENV PATH="/opt/nikto/program:${PATH}"
 
# Install nuclei
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
ENV PATH="/root/go/bin:${PATH}"
 
# Copy requirements
COPY requirements.txt .
 
RUN pip install --no-cache-dir -r requirements.txt
 
# Copy app
COPY . .
 
EXPOSE 5005
 
CMD ["python", "app.py"]