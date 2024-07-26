from multiprocessing import Queue
from os import path
from abstracts.observer import IObserver
from termcolor import colored
from typing import Tuple
import os

class Logger(IObserver):
    def __init__(self,
                 name,
                 output_dir: str):
        """
        :param name: name of observable
        :param output_dir: path where results.txt will be to log the txt to it
        """
        self.name = name
        self.results_file_path = os.path.join(output_dir, 'results.txt')
        self.errors_file_path = os.path.join(output_dir, 'errors.log')

    def print_to_cli(
        self, normal_txt: str, colored_txt: str, end: str, color: str):
        normal_txt = str(normal_txt)
        colored_txt = colored(str(colored_txt), color)
        blue_name = colored(f'[{self.name}] ', 'blue')
        print(f"{blue_name}"
              f"{colored_txt}"
              f"{normal_txt}",
              end=end)

    def log_to_file(self, normal_txt, green_txt, file_path: str):
        with open(file_path, 'a') as f:
            f.write(f"[{self.name}] {green_txt} {normal_txt}\n")

    def update(self, msg: Tuple[str,str]):
        """
        writes the given txt to results.txt file and cli
        each msg should consist of the following
        normal_txt: not colored text to be written in the CLI
        green_txt: text to be written in green in the CLI
        log_to_results_file: bool. if False, we won't log the text to
        results.txt and
        it will only be written in the CLI, used when regularly printing
        the number of flows parsed etc.
        end: \n \r "" etc. same as print()'s end
        """
        normal_txt, colored_txt, log_to_results_file, end, error = msg
        color = "red" if error else "green"
        self.print_to_cli(normal_txt, colored_txt, end, color)
            
        if log_to_results_file:
            self.log_to_file(normal_txt, colored_txt, self.results_file_path)
        if error:
            self.log_to_file(normal_txt, colored_txt, self.errors_file_path)

