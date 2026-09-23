#!/bin/bash
# Note: We don't use 'set -e' here to avoid exiting the container on non-critical failures

# Configuration from template
REPO_URL="https://github.com/labd/wagtail-2fa"
COMMIT_HASH="1149068b924ad7a30e165a9cb90d2b791432f267"

echo "Setting up SCRBench environment..."
echo "Repository: $REPO_URL"
echo "Commit: $COMMIT_HASH"

# Clone the repository
echo "Cloning repository..."
if ! git clone "$REPO_URL.git" repo; then
    echo "ERROR: Failed to clone repository $REPO_URL"
    exit 1
fi

cd repo

# Checkout the specific commit
echo "Checking out commit $COMMIT_HASH..."
if ! git checkout "$COMMIT_HASH"; then
    echo "ERROR: Failed to checkout commit $COMMIT_HASH"
    echo "Available commits:"
    git log --oneline -10
    exit 1
fi

echo "Successfully checked out commit: $(git rev-parse --short HEAD)"

# Revert the commit into staged changes for code review
echo "Setting up code review environment..."
echo "Reverting commit to show changes as staged modifications..."
if ! git reset HEAD~1; then
    echo "WARNING: Failed to reset to previous commit"
else
    echo "Successfully reset to previous commit"
fi

# Stage all changes (including new files) for review
if ! git add -N .; then
    echo "WARNING: Failed to stage intent-to-add files"
else
    echo "Successfully staged all changes for review"
fi

# Display final environment status
echo ""
echo "=== SCRBench Environment Ready ==="
echo "Repository: $REPO_URL"
echo "Base commit: $(git rev-parse --short HEAD) ($(git log -1 --format='%s'))"
echo "Working directory: /workspace/repo"
echo ""
echo "📋 Code Review Status:"
git status --short | head -10
if [ $(git status --porcelain | wc -l) -gt 10 ]; then
    echo "   ... and $(($(git status --porcelain | wc -l) - 10)) more files"
fi

# Ensure we're in the correct working directory
cd /workspace/repo

# Setup complete - the CMD from Dockerfile will start the shell
echo "Setup complete! Starting interactive shell in /workspace/repo..."