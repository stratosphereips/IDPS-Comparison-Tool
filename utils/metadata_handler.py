import datetime
import os
import sys
from typing import (
    Callable,
    Optional,
    Tuple,
    )

from git import Repo


class MetadataHandler:
    def __init__(self, main):
        self.main = main
        
    def get_human_readable_datetime(self) -> str:
        now = datetime.datetime.now()
        return now.strftime("%A, %B %d, %Y %H:%M:%S")
    
    
    def get_git_info(self) -> Optional[Tuple[str, str]]:
        """
        Returns a tuple containing (commit,branch)
        """
        try:
            repo = Repo(".")
            # add branch name and commit
            branch = repo.active_branch.name
            commit = repo.active_branch.commit.hexsha
            return commit, branch
        except Exception:
            # for when there's no .git files for any reason
            return
        
        
    def add_metadata(self):
        """
        Adds tool versions and files used
        to metadata.txt in the outupt dir
        """
        metadata_file = os.path.join(self.main.output_dir, 'metadata.txt')
        self.main.log("Storing metadata in: ", metadata_file)
        gt = self.main.args.ground_truth_dir or self.main.args.ground_truth_file
        metadata_to_log = (f"Timestamp: "
                   f"{self.get_human_readable_datetime()}\n\n"
                   f"Used cmd: {' '.join(sys.argv)}\n\n"
                   f"Slips version: {self.main.slips_version} \n\n"
                   f"Suricata version: {self.main.suricata_version}\n\n"
                   f"Ground truth: {gt}\n\n"
                   f"Slips DB: {self.main.args.slips_db}\n\n"
                   f"Suricata file: {self.main.args.eve_file}\n\n"
                   f"Output directory: {self.main.output_dir}\n\n")
        
        if git_into := self.get_git_info():
            commit, branch = git_into
            metadata_to_log += (f"Branch: {branch}\n\n"
                                f"Commit: {commit}")
            
        with open(metadata_file, 'w') as metadata:
            metadata.write(metadata_to_log)