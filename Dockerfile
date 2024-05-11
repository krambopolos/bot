# Use a full Python base image
FROM python:3.8

# Set the working directory in the container
WORKDIR /app

# Install system dependencies including build tools
RUN apt-get update && apt-get install -y \
        wget \
        git \
        ca-certificates \
        build-essential \
        && rm -rf /var/lib/apt/lists/*

# Download and install Go
ENV GO_VERSION 1.22.3
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz

# Set environment variables for Go
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Install Go-based tools one by one to identify the problematic installation
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN GO111MODULE=on go install github.com/jaeles-project/gospider@latest

# Copy the Python requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project files into the container
COPY . .

# Expose port if necessary
# EXPOSE 5000

# Command to run the application
CMD ["tail", "-f", "/dev/null"]
