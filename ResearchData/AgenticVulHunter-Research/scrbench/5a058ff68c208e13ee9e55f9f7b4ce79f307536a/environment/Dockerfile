FROM python:3.11-slim

WORKDIR /workspace

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy the setup script
COPY setup_repo.sh /workspace/setup_repo.sh
RUN chmod +x /workspace/setup_repo.sh

# Create a wrapper script that sets working directory properly
RUN echo '#!/bin/bash\n/workspace/setup_repo.sh\ncd /workspace/repo\nexec "$@"' > /workspace/entrypoint.sh && chmod +x /workspace/entrypoint.sh

# Use the wrapper as entrypoint and bash as default command
ENTRYPOINT ["/workspace/entrypoint.sh"]
CMD ["/bin/bash"]