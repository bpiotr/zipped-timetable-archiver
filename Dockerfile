FROM python:3.6

RUN apt-get update && apt-get install -y git

COPY requirements.txt /workspace/requirements.txt

RUN pip install -r /workspace/requirements.txt

RUN chown -R nobody /workspace

USER nobody

COPY mpk_archiver.py /workspace/mpk_archiver.py
COPY ssh_wrapper.sh /workspace/ssh_wrapper.sh

ENTRYPOINT ["python", "/workspace/mpk_archiver.py"]
CMD ["-d", "600", "-url", "git@github.com:bpiotr/rozklad-mpk-wroclaw.git", "https://www.wroclaw.pl/open-data/dataset/rozkladjazdytransportupublicznegoplik_data/resource/1afcb920-d26d-4106-9a6a-e70d7a1642ad"]