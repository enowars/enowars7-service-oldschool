FROM python:3.9-buster

RUN apt update && apt install -y php

RUN useradd -ms /bin/bash -u 1000 checker

# fix pycurses terminfo warnings
ENV TERM=linux
ENV TERMINFO=/etc/terminfo

COPY ./src/ /checker/
WORKDIR /checker
RUN chown checker -R /checker

USER checker
RUN python3 -m pip install --no-warn-script-location -r requirements.txt

ENTRYPOINT [ "/home/checker/.local/bin/gunicorn", "-c", "gunicorn.conf.py", "checker:app" ]
