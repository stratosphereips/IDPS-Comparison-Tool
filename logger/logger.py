from multiprocessing import Queue
from os import path
from abstracts.observer import IObserver
from termcolor import colored
from typing import Tuple

class Logger(IObserver):
    def __init__(self,
                 name,
                 results_path: str):
        """
        :param name: name of observable
        :param results_path: path to results.txt to log the txt to
        """
        self.name = name
        self.results_path = results_path

    def print_to_cli(self, normal_txt, green_txt):
        normal_txt = str(normal_txt)
        green_txt = str(green_txt)
        print(colored(f'[{self.name}] ', 'blue') + colored(green_txt,'green') + normal_txt)

    def log_to_results_file(self, normal_txt, green_txt):
        with open(self.results_path, 'a') as results:
            results.write(f"[{self.name}] {green_txt} {normal_txt}\n")

    def update(self, msg: Tuple[str,str]):
        """
        writes the given txt to results.txt file and cli
        each msg should consist of the following
        normal_txt: not colored text to be written in the CLI
        green_txt: text to be written in green in the CLI
        log_to_results_file: bool. if False, we won't log the text to results.txt and
            it will only be written in the CLI, used when regularly printing the number of flows parsed etc.
        """
        normal_txt, green_txt, log_to_results_file = msg

        self.print_to_cli(normal_txt, green_txt)

        if not log_to_results_file:
            return
        self.log_to_results_file(normal_txt, green_txt)


