from abc import ABC, abstractmethod
class IObserver(ABC):
    """
    gets notified whenever an observable has a new msg for it
    """
    @abstractmethod
    def update(self, message):
        """gets called whenever there's a new msg"""
        pass

class IOvservable(ABC):
    def __init__(self, results_path: str):
        self.results_path = results_path
        self.observers = []
        # self.queue = Queue()

    def add_observer(self, observer):
        self.observers.append(observer)

    def remove_observer(self, observer):
        self.observers.remove(observer)

    def notify_observers(self, message):
        for observer in self.observers:
            observer.update(message)