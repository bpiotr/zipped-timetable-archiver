import datetime
import hashlib
import bs4
import requests
import tempfile
import sched, time
import logging
import pathlib


def configure_logging():
    l = logging.getLogger("mpk_archiver")
    l.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    l.addHandler(ch)
    return l


logger = configure_logging()

ARCHIVER_SSH_KEY = "ARCHIVER_SSH_KEY"

try:
    import urllib.request as request
except ImportError:
    import urllib as request
from argparse import ArgumentParser
import zipfile

import os
from collections import namedtuple
from dateutil.parser import parse as parse_date_string
from git import Repo

UpdateLogEntry = namedtuple("UpdateLogEntry", ["registered", "checksum", "commit"])

SCRIPT_PATH = os.path.realpath(__file__)
SCRIPT_DIR = os.path.dirname(SCRIPT_PATH)
KEY_PATH = os.path.join(SCRIPT_DIR, "ssh_key")
SSH_WRAPPER_PATH = os.path.join(SCRIPT_DIR, "ssh_wrapper.sh")


class PeriodicScheduler(object):
    def __init__(self):
        self.scheduler = sched.scheduler(time.time, time.sleep)

    def setup(self, interval, action, actionargs=()):
        action(*actionargs)
        self.scheduler.enter(interval, 1, self.setup,
                             (interval, action, actionargs))

    def run(self):
        self.scheduler.run()


def main(local_git_path, remote_git_url, timetable_url):
    logger.info("Updating local repository at %s from %s.", local_git_path, remote_git_url)
    local_repo = update_local_git_repo(local_git_path, remote_git_url)
    logger.info("Done.")

    logger.info("Looking for newest log entry...")
    latest_log_entry = get_newest_log_entry(local_git_path)
    logger.info("Done: '%s'.", latest_log_entry)

    logger.info("Downloading %s...", timetable_url)
    temp_file_path = download_file(timetable_url)
    logger.info("Done: %s.", temp_file_path)

    logger.info("Calculating checksum of the downloaded file...")
    new_checksum = calculate_checksum(temp_file_path)
    logger.info("Done: '%s'.", new_checksum)

    if not latest_log_entry or new_checksum != latest_log_entry.checksum:
        logger.info("NEW TIMETABLE DETECTED. Checksum of the downloaded data is different than the newest log entry.")
        logger.info("Extracting downloaded archive...")
        files_extracted = extract_new_file(temp_file_path, local_git_path)
        logger.info("Done: %s", files_extracted)

        current_utc_time = datetime.datetime.utcnow()
        local_repo.index.add(files_extracted)

        for now_missing_file in pathlib.Path(local_git_dir).rglob("*.txt").filter(lambda p: str(p) not in files_extracted):
            local_repo.index.remove(str(now_missing_file))

        logger.info("Committing extracted files...")
        new_files_commit = local_repo.index.commit("Nowy rozkład: {}".format(current_utc_time))
        logger.info("Done: %s.", new_files_commit)

        logger.info("Inserting and committing new log entry...")
        new_log_entry = UpdateLogEntry(current_utc_time, new_checksum, new_files_commit.hexsha)
        insert_log_entry_in_table(local_git_path, new_log_entry)
        local_repo.index.add([os.path.join(local_git_path, "README.md")])
        log_modification_commit = local_repo.index.commit("Nowy wpis w logu {}".format(current_utc_time))
        logger.info("Done: %s.", log_modification_commit)

        logger.info("Pushing changes to %s...", remote_git_url)
        local_repo.remote().push()
        logger.info("Done")
    else:
        logger.info("Checksum of the downloaded data is the same as the newest log entry. No action made.")


def _read_ssh_key_from_env_and_save():
    ssh_key = os.getenv(ARCHIVER_SSH_KEY)
    if not ssh_key:
        logger.info("'ARCHIVER_SSH_KEY; is not specified. Using user's default SSH config.")
        return
    logger.info("Saving $ARCHIVER_SSH_KEY to {}".format(KEY_PATH))

    if os.path.exists(KEY_PATH):
        os.chmod(KEY_PATH, 0o700)
    with open(KEY_PATH, "w") as f:
        f.write(ssh_key)
    os.chmod(KEY_PATH, 0o400)


def _parse_cli_args():
    arg_parser = ArgumentParser()
    arg_parser.add_argument("-url", "--remote_git_url", help="URL to remote git repo.")
    arg_parser.add_argument("-d", "--delay", help="Interval of waiting between checks.", type=int)
    arg_parser.add_argument("download_url", help="URL to download page.")

    args = arg_parser.parse_args()
    return args.remote_git_url, args.download_url, args.delay


def download_file(download_url):
    page = requests.get(download_url)
    if (page.status_code != 200):
        page.raise_for_status()
    mpk_data_tree = bs4.BeautifulSoup(page.text, "html.parser")
    link = mpk_data_tree.find("a", {"class": "resource-url-analytics"})
    path, http_message = request.urlretrieve(link.get("href"))
    return path


def cleanup(temp_file):
    if temp_file and os.path.exists(temp_file):
        os.chmod(temp_file, 0o500)
        os.remove(temp_file)
    request.urlcleanup()


def calculate_checksum(file_path):
    def hash_bytestr_iter(bytesiter, hasher):
        for block in bytesiter:
            hasher.update(block)
        return hasher.hexdigest()

    def file_as_blockiter(file_path, blocksize=65536):
        with open(file_path, "rb") as afile:
            block = afile.read(blocksize)
            while len(block) > 0:
                yield block
                block = afile.read(blocksize)

    return hash_bytestr_iter(file_as_blockiter(file_path), hashlib.sha256())


def extract_new_file(path_to_zip, destination_dir):
    with zipfile.ZipFile(path_to_zip, 'r') as zip_ref:
        all_members = zip_ref.infolist()
        non_dir_members = filter(lambda info: not info.filename.endswith("/"), all_members)
        files_in_zip = map(lambda info: os.path.join(destination_dir, info.filename), non_dir_members)
        zip_ref.extractall(destination_dir)
    return list(files_in_zip)


def get_newest_log_entry(local_git_path):
    log_file_content = _get_all_logfile_contents(local_git_path)

    log_table_lines = filter(lambda s: s.startswith("|"), log_file_content)
    log_table_lines = list(map(lambda s: s.strip("|").split("|"), list(log_table_lines)[2:]))

    log_entries = []
    for row in log_table_lines:
        registered = parse_date_string(row[0].strip())
        checksum = row[1].strip()
        commit_hash = row[2].strip()
        log_entries.append(UpdateLogEntry(registered, checksum, commit_hash))

    return max(log_entries, key=lambda e: e.registered) if log_entries else None


def insert_log_entry_in_table(local_git_path, new_log_entry):
    log_file_content = _get_all_logfile_contents(local_git_path)
    table_at = 0
    for i in range(len(log_file_content)):
        if log_file_content[i].startswith("|"):
            table_at = i
            break
    log_file_content.insert(table_at + 2, log_entry_to_text(new_log_entry))

    with open(os.path.join(local_git_path, "README.md"), "w") as file:
        for line in log_file_content:
            file.write(line)


def log_entry_to_text(log_entry: UpdateLogEntry):
    return "| {} | {} | {} |\n".format(log_entry.registered, log_entry.checksum, log_entry.commit)


def _get_all_logfile_contents(local_git_path):
    log_file_name = os.path.join(local_git_path, "README.md")
    with open(log_file_name) as file:
        log_file_content = file.readlines()
    return log_file_content


def update_local_git_repo(local_repo_path, remote_repo_url=None):
    env = {"GIT_SSH": SSH_WRAPPER_PATH}
    if not os.path.exists(os.path.join(local_repo_path, ".git")):
        if not remote_repo_url:
            raise Exception("You must pass remote GIT URL if the local repo does not exist.")
        logger.info("Cloning repo from %s to %s ...", remote_git_url, local_repo_path)
        local_repo = Repo.clone_from(remote_repo_url, local_repo_path, env=env)
    else:
        local_repo = Repo(local_repo_path)

    local_repo.git.update_environment(**env)
    origin = local_repo.remote()
    origin.pull()
    return local_repo


if __name__ == '__main__':
    _read_ssh_key_from_env_and_save()

    remote_git_url, timetable_url, delay = _parse_cli_args()
    local_git_dir = tempfile.TemporaryDirectory("_mpk")

    try:
        s = PeriodicScheduler()
        s.setup(delay, main, (local_git_dir.name, remote_git_url, timetable_url))
        s.run()
    finally:
        logger.info("Cleaning %s", KEY_PATH)
        cleanup(KEY_PATH)
        logger.info("Cleaning %s", local_git_dir.name)
        local_git_dir.cleanup()
        logger.info("Done.")

