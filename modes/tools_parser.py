from multiprocessing import (
    Process,
    Event,
    )
from typing import List

from parsers.arg_parser import ArgsParser
from parsers.ground_truth import GroundTruthParser
from parsers.slips import SlipsParser
from parsers.suricata import SuricataParser


class ToolsParser:
    """responsible for starting parsers for each given tool/gt"""
    def __init__(self,
                 output_dir: str,
                 results_path: str,
                 print_stats_event: Event ):
        self.output_dir = output_dir
        self.results_path = results_path
        self.print_stats_event = print_stats_event
        
        args = ArgsParser().args
        # each type of supported gt input goes here, the goal is to be able
        # to start and join them before other parsers start.
        self.gt_map = {
            args.ground_truth_dir: GroundTruthParser,
            args.ground_truth_file: GroundTruthParser,
            }
        self.tools_map = {
            args.slips_db: SlipsParser,
            args.eve_file: SuricataParser,
            }
        
    def start(self, parser, *args):
        """
        this function starts in a new Process
        used to init the given parser with the given args
        :param parser: An obj of any parser in parsers/
        :param args: args required for starting the given parser
        :return: None
        """
        p = parser(*args)
        p.log(f"Starting {p.name}:", f" {args[-1]}")
        p.parse()
        
    def start_gt_parsers(self) -> List[Process]:
        """
        starts a thread for each given gt path
        :return: returns a list of started processes
        """
        processes = []
        for arg, parser in self.gt_map.items():
            # this arg is the path of the given file/db to parse
            if not arg:
                continue
                
            proc = Process(
                target=self.start,
                args=(
                    parser,
                    self.output_dir,
                    self.results_path,
                    arg)
            )
            proc.start()
            processes.append(proc)
        return processes

    def start_tool_parsers(self) -> List[Process]:
        """
        starts a thread for each given tool parser
        :return: returns a list of started processes
        """
        started_processes = []
        for arg, parser in self.tools_map.items():
            # this arg is the path of the given file/db to parse
            if not arg:
                continue
                
            proc = Process(
                target=self.start,
                args=(
                    parser,
                    self.output_dir,
                    self.results_path,
                    arg),
                name = parser.name
            )
            proc.start()
            started_processes.append(proc)
        return started_processes
    
    
    def start_parsers(self):
        """
        runs each parser in a separate proc and returns when they're all done
        :param print_stats_event: the thread will set this event when it's
        done reading the ground truth flows and
        started reading slips and suricata flows so the print_stats
        thread can start printing
        """
        # the gt parsers should finish first before starting tool parsers
        
        processes: List[Process] = self.start_gt_parsers()
        for proc in processes:
            proc.join()
            
        self.print_stats_event.set()
        
        processes: List[Process] = self.start_tool_parsers()
        for proc in processes:
            proc.join()
            
        
            

            
            
    

    