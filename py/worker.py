from PyQt5.QtCore import pyqtSignal, QThread


class WorkerThread(QThread):
    """
    A thread that takes a job. When started with the start slot, the thread
    runs the job to completion and emits the finished signal.

    This worker cannot directly manipulate the GUI. Attempting to do so will
    get errors like `QObject::setParent: Cannot set parent, new parent is in a
    different thread`
    Signals should be used to tell the main thread (which controls the GUI)
    to modify or add GUI elements.
    Creating GUI elements and passing them as signal parameters to the main
    thread is OK.

    Implementation based on: https://stackoverflow.com/a/41605909/
    And: https://woboq.com/blog/qthread-you-were-not-doing-so-wrong.html
    The latter blog post explains that inheriting from QThread makes sense
    when you don't really need an event loop.
    """
    def __init__(self):
        self.job_func = None
        super().__init__()

    def run_job(self, job_func):
        self.job_func = job_func
        self.start()

    def run(self):
        """
        Overridden method. This is called upon receiving the start signal.
        When this method returns, the finished signal is emitted.
        """
        if not self.job_func:
            raise ValueError(
                "Don't start this worker directly. Call run_job() instead.")

        self.job_func()
        self.job_func = None
