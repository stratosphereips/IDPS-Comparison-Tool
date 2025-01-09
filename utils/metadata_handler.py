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
        self.metadata_file_path = os.path.join(self.main.output_dir,
                                          'metadata.txt')
        # clear the file
        open(self.metadata_file_path, 'w').close()
        self._handle = open(self.metadata_file_path, 'a')
        
    def __del__(self):
        self._handle.close()

    def get_datetime_now(self) -> str:
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
        
    
    def add_end_time(self) -> str:
        end_time = self.get_datetime_now()
        self._handle.write(f"End time: {end_time}\n\n")
        return end_time
    
    def add_analysis_time(self, analysis_time):
        self._handle.write(f"Analysis time: {analysis_time} seconds\n\n")
    
    def add_metadata(self):
        """
        Adds tool versions and files used
        to metadata.txt in the outupt dir
        """
        self.main.log("Storing metadata in: ", self.metadata_file_path)
        gt = self.main.args.ground_truth_dir or self.main.args.ground_truth_file
        metadata_to_log = (
                   f"Used cmd: {' '.join(sys.argv)}\n\n"
                   f"Slips version: {self.main.slips_version} \n\n"
                   f"Suricata version: {self.main.suricata_version}\n\n"
                   f"Ground truth: {gt}\n\n"
                   f"Slips DB: {self.main.args.slips_db}\n\n"
                   f"Suricata file: {self.main.args.eve_file}\n\n"
                   f"Output directory: {self.main.output_dir}\n\n"
                   f"Start time: {self.get_datetime_now()}\n"
        )
        if git_into := self.get_git_info():
            commit, branch = git_into
            metadata_to_log += (f"Branch: {branch}\n\n"
                                f"Commit: {commit}\n\n")
            
        self._handle.write(metadata_to_log)
        