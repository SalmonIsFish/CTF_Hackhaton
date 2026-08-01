# Isolate Execution (organizer's Next Steps slide, harness element #5). Containerizes
# agent/api.py (the FastAPI bridge) so a crash or resource runaway in the agent process
# can't touch the host: non-root user, read-only root filesystem at run time, no shell
# surface added beyond what the base image already has. This is process/filesystem
# isolation, NOT per-challenge dynamic network egress control -- the network tools
# (fetch_url/tcp_open/port_scan) are pure Python with no subprocess/shell surface, so
# there's nothing here for Docker to sandbox that isn't already sandboxed by having no
# shell access in the first place. Host allowlisting stays enforced the existing way, in
# Python, via extract_allowed_hosts()/act() in agent/graph.py -- see NEXT_STEPS.md for the
# honest scope note.
FROM python:3.14-slim

WORKDIR /app

# Install dependencies first so this layer is cached across code-only rebuilds.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Only what the running agent actually reads: agent/ (code), vault/ and .agents/skills/
# (read-only reference content the search_vault/search_skills tools load). Deliberately
# not the whole repo -- evals/, demo/, .git/, etc. never need to be inside the container.
COPY agent/ ./agent/
COPY vault/ ./vault/
COPY .agents/skills/ ./.agents/skills/

# Non-root: a compromised or buggy process inside the container can't act as root even
# though the container itself isn't meaningfully more privileged than the host process
# would have been.
RUN useradd --create-home --shell /usr/sbin/nologin app \
    && chown -R app:app /app
USER app

EXPOSE 8000

# LangGraph's checkpointer here is MemorySaver (in-process, no disk writes), and
# evals/run_log.jsonl's local telemetry log is best-effort (agent/graph.py's log_run()
# catches OSError and never raises) -- so a read-only root filesystem at `docker run`
# time (--read-only, see docker-compose.yml) doesn't break anything the agent needs to do.
CMD ["uvicorn", "agent.api:app", "--host", "0.0.0.0", "--port", "8000"]
