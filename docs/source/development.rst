Development
###########

::

    git clone https://github.com/pyobs/pyobs-auth.git
    cd pyobs-auth
    uv sync --group dev
    uv run pytest
    uv run ruff check pyobs_auth/
    uv run black --check .
    uv run pyrefly check pyobs_auth
