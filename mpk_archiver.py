import datetime
import hashlib
import urllib.request as request
from argparse import ArgumentParser
import zipfile

import os
from collections import namedtuple
from dateutil.parser import parse as parse_date_string
from git import Repo

UpdateLogEntry = namedtuple("UpdateLogEntry", ["registered", "checksum", "commit"])


def main():
    arg_parser = ArgumentParser()
    arg_parser.add_argument("-g", "--local_git_path", help="Path to the local git repo.")
    arg_parser.add_argument("-url", "--remote_git_url", help="URL to remote git repo.")
    arg_parser.add_argument("download_url", help="URL to file to be downloaded, unzipped and placed in the repo.")

    args = arg_parser.parse_args()

    local_repo = update_local_git_repo(args.local_git_path, args.remote_git_url)
    print(local_repo)

    latest_log_entry = get_newest_log_entry(args.local_git_path)
    print(latest_log_entry)

    try:
        temp_file_path = download_file(args.download_url)
        print(temp_file_path)

        new_checksum = calculate_checksum(temp_file_path)
        print(new_checksum)

        if not latest_log_entry or new_checksum != latest_log_entry.checksum:
            files_extracted = extract_new_file(temp_file_path, args.local_git_path)
            print(files_extracted)
            utcnow = datetime.datetime.utcnow()

            local_repo.index.add(files_extracted)
            commit = local_repo.index.commit("Nowy rozkład: {}".format(utcnow))

            new_log_entry = UpdateLogEntry(utcnow, new_checksum, commit.hexsha)
            print(new_log_entry)

            insert_log_entry_in_table(args.local_git_path, new_log_entry)

            local_repo.index.add([os.path.join(args.local_git_path, "README.md")])
            local_repo.index.commit("Nowy wpis w logu {}".format(utcnow))

            # push
            local_repo.remote().push()
    finally:
        cleanup()


def download_file(download_url):
    path, http_message = request.urlretrieve(download_url)
    return path


def cleanup():
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


def update_local_git_repo(local_repo_path, remote_repo_url=None):
    if not os.path.exists(local_repo_path):
        if not remote_repo_url:
            raise Exception("You must pass remote GIT URL if the local repo does not exist.")
        local_repo = Repo.clone_from(remote_repo_url, local_repo_path)
    else:
        local_repo = Repo(local_repo_path)

    # if local_repo.is_dirty():
    #     raise Exception("Local repo is dirty. Clean it up.")

    origin = local_repo.remote()
    origin.pull()

    return local_repo


if __name__ == '__main__':
    exit(main())