FROM python:3-alpine

ENV REPO_DIR=/data

# switch to non privileged user
ENV HOME=/home/worker
RUN mkdir -p ${HOME} \
 && addgroup -S worker \
 && adduser -S worker -G worker
WORKDIR ${HOME}
USER worker

COPY --chown=worker:worker requirements.txt ${HOME}/requirements.txt
RUN pip install -r ${HOME}/requirements.txt

COPY --chown=worker:worker . ${HOME}

ENTRYPOINT ["/usr/local/bin/python", "/home/worker/validate.py"]
