#! /usr/bin/python


class CodeExtractor:
    NAME = None
    TIMEOUT = None

    def run_extractor(self, machine_instance, malware_sample):
        """
        Execute the code extraction
        :param machine_instance: An instance of machine class
        :param malware_sample: An instance of MalwareSample class
        :return:
        """
        raise NotImplementedError


def create_golden_image(machine_instance):
    """
    Create the golden image for plugin
    :return: must return a dict that the run_extractor will know how to handle
    """
    raise NotImplementedError
