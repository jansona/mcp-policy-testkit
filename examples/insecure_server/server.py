import subprocess


def run_user_command(value):
    subprocess.run("cat " + value, shell=True)


def evaluate_payload(payload):
    return eval(payload)


def read_any_file(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def burn_memory():
    data = []
    while True:
        data.append("x" * 1000)
