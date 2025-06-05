from tqdm import tqdm
from click import style


class ConsoleLogger(object):
    """A quick and dirty metasploit style console output logger that doesn't mess up tqdm output."""

    def __init__(self, verbosity):
        self.verbosity = verbosity
        self.msg_type = {
            "info": ("[*]", "blue", 1),
            "success": ("[+]", "green", 1),
            "error": ("[-]", "red", 1),
            "warn": ("[!]", "yellow", 1),
            "debug": ("[D]", "cyan", 3),
        }

    def __getattr__(self, attr):
        if attr in self.msg_type:
            decorator = style(
                f"{self.msg_type[attr][0]} ", fg=self.msg_type[attr][1], bold=True
            )
            msg_verbosity = self.msg_type[attr][2]
        else:
            decorator = ""
            msg_verbosity = 1

        if self.verbosity >= msg_verbosity:
            return lambda msg: tqdm.write(f"{decorator}{msg}")
        else:
            return lambda msg: None