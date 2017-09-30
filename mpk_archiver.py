import datetime
import hashlib
import tempfile

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


def main():
    local_git_path, remote_git_url, timetable_url = _parse_cli_args()

    key_path = None

    try:
        ssh_key = os.getenv("ssh_key")
        if not ssh_key:
            raise Exception("'ssh_key' env variable must be specified!")
        key_file, key_path = tempfile.mkstemp(dir="/opt/app-root")
        with open(key_file) as f:
            f.write(ssh_key)
        os.chmod(key_path, 0o400)

        print("Updating local repository at {} from {}.".format(local_git_path, remote_git_url))
        local_repo = update_local_git_repo(local_git_path, key_path, remote_git_url)
        print("Done.")

        print("Looking for newest log entry...")
        latest_log_entry = get_newest_log_entry(local_git_path)
        print("Done: '{}'.".format(latest_log_entry))

        print("Downloading {}...".format(timetable_url))
        temp_file_path = download_file(timetable_url)
        print("Done: {}.".format(temp_file_path))

        print("Calculating checksum of the downloaded file...")
        new_checksum = calculate_checksum(temp_file_path)
        print("Done: '{}'.".format(new_checksum))

        if not latest_log_entry or new_checksum != latest_log_entry.checksum:
            print("NEW TIMETABLE DETECTED. Checksum of the downloaded data is different than the newest log entry.")
            print("Extracting downloaded archive...")
            files_extracted = extract_new_file(temp_file_path, local_git_path)
            print("Done: {}".format(files_extracted))

            current_utc_time = datetime.datetime.utcnow()
            local_repo.index.add(files_extracted)
            print("Committing extracted files...")
            new_files_commit = local_repo.index.commit("Nowy rozkład: {}".format(current_utc_time))
            print("Done: {}.".format(new_files_commit))

            print("Inserting and committing new log entry...")
            new_log_entry = UpdateLogEntry(current_utc_time, new_checksum, new_files_commit.hexsha)
            insert_log_entry_in_table(local_git_path, new_log_entry)
            local_repo.index.add([os.path.join(local_git_path, "README.md")])
            log_modification_commit = local_repo.index.commit("Nowy wpis w logu {}".format(current_utc_time))
            print("Done: {}.".format(log_modification_commit))

            print("Pushing changes to {}...".format(remote_git_url))
            local_repo.remote().push()
            print("Done")
        else:
            print("No new timetable detected. Checksum of the downloaded data is the same as the newest log entry.")
    finally:
        cleanup(key_path)


def _parse_cli_args():
    arg_parser = ArgumentParser()
    arg_parser.add_argument("-g", "--local_git_path", help="Path to the local git repo.")
    arg_parser.add_argument("-url", "--remote_git_url", help="URL to remote git repo.")
    arg_parser.add_argument("download_url", help="URL to file to be downloaded, unzipped and placed in the repo.")
    args = arg_parser.parse_args()
    local_git_path = args.local_git_path
    remote_git_url = args.remote_git_url
    timetable_url = args.download_url
    return local_git_path, remote_git_url, timetable_url


def download_file(download_url):
    path, http_message = request.urlretrieve(download_url)
    return path


def cleanup(temp_file):
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
    log_file_content.insert(table_at+2, log_entry_to_text(new_log_entry))

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


def update_local_git_repo(local_repo_path, key_path, remote_repo_url=None):
    env = {"GIT_SSH": "ssh -i {}".format(key_path)}
    if not os.path.exists(local_repo_path):
        if not remote_repo_url:
            raise Exception("You must pass remote GIT URL if the local repo does not exist.")
        local_repo = Repo.clone_from(remote_repo_url, local_repo_path, env=env)
    else:
        local_repo = Repo(local_repo_path)
        local_repo.git.update_environment(**env)

    origin = local_repo.remote()
    origin.pull()
    return local_repo


if __name__ == '__main__':
    exit(main())