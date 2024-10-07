FROM handsonsecurity/seed-ubuntu:large

RUN apt-get update && apt-get upgrade -y && apt-get install -y libgtk-3-0 libgstreamer-plugins-base1.0-0 libmpv-dev build-essential software-properties-common

RUN apt-get update && add-apt-repository ppa:ubuntu-toolchain-r/test -y
# RUN apt-get update && add-apt-repository ppa:deadsnakes/ppa -y

RUN apt-get update && apt-get install -y gcc-11 g++-11 python3

RUN apt-get upgrade -y

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y zenity

RUN curl https://bootstrap.pypa.io/get-pip.py | python3

COPY requirements.txt ./
RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["flet", "run", "-r", "/volumes/ids-gui.py"]
