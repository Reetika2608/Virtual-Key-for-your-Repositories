from distutils.cmd import Command
from pylint import lint

import sys


class PylintCommand(Command):
    """
    Custom setup.py command to lint project using Pylint
    """
    description = "Runs Pylint and fails if the score is under a certain threshold"
    user_options = [('min-quality=', 'q', 'minimum quality')]

    def initialize_options(self):
        self.min_quality = 7.3

    def finalize_options(self):
        pass

    def run(self):
        """
        This runs Pylint against the source code and extracts the
        quality score. If it is below a certain threshold (min_quality)
        then the stage fails.
        """
        try:
            min_score = float(self.min_quality)
        except ValueError:
            print("ERROR: Parameter --min-quality must be a float")
            sys.exit(1)

        run = lint.Run(["src/base_platform", "src/cafedynamic", "src/managementconnector", "src/unittests"], exit=False)
        actual_score = run.linter.stats['global_note']

        if actual_score < min_score:
            print("FAILURE: Code quality was {} and it must be greater than {}".format(actual_score, min_score))
            sys.exit(1)

        print("SUCCESS: Code quality was {} which is greater than the threshold {}".format(actual_score, min_score))
