from optparse import OptionParser
from unpacker import deEmotet
from dump_parser import SimplePEFileParser
import base64 as b64
import hashlib
import glob
import sys
import os


__author__ = "d00rt - @D00RT_RM"

__version__ = "1.0.0"
__maintainer__ = "d00rt - @D00RT_RM"
__email__ = "d00rt.fake@gmail.com"
__status__ = "Testing"


VALID_OUTPUTS = [
    "plaintext",
    "json",
]

LOG_ERRORS = False

def log_error(message):
    if LOG_ERRORS == True:
        print message

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def print_plaintext(data):
    print "filename: {0}".format(data["filename"])
    print "md5: {0}".format(data["md5"])
    print "unpacked: {0}".format(data["unpacked"])
    print "number_of_rsa_keys: {0}".format(data["number_of_rsa_keys"])
    print "number_of_ips: {0}".format(data["number_of_ips"])
    
    if data.get("rsa_keys", False):
        print "rsa_key: "
        for r in data["rsa_keys"]:
            print "    {0}".format(b64.b64encode(r))

    if data.get("ips", False):
        print "command and controls: "
        for r in data["ips"]:
            print "    {0}".format(r)


def print_json(data):
    print data


def print_metadata(meta, filename, frmt, verbose=False):
    unpacked, rsa_keys, ips, m1, m2 = meta
    data = {
        "filename": filename,
        "md5": md5(filename),
        "unpacked": unpacked,
        "number_of_rsa_keys": len(rsa_keys),
        "number_of_ips": len(ips),
        "match_1": m1,
        "match_2": m2,
    }

    if verbose:
        verbose_data = {
            "rsa_keys": rsa_keys,
            "ips": ips,
        }
        data.update(verbose_data)

    if frmt == "plaintext":
        print_plaintext(data)

    if frmt == "json":
        print_json(data)


def run_folder(folder, debug_log, verbose, frmt, write_results=False):
    for filename in glob.glob(os.path.join(folder, "*")):
        if not os.path.isdir(filename):
            run_file(filename, debug_log, verbose, frmt, gui=False, write_results=write_results)

        else:
            log_error("[!] Error. The file {0} is a folder.".format(filename))


def run_file(filename, debug_log, verbose, frmt, gui=False, write_results=False):
    if gui:
        # If gui == True -> the output will automatically saved
        EmotetUnpacker = deEmotet(gui=gui, debug=debug_log)
        unpacking_result = EmotetUnpacker.unpack_file(filename)
        return

    try:
        SimplePEFileParser(filename=filename)
    except Exception as e:
        log_error("[!] Error. {0} {1}".format(filename, e))
        return

    EmotetUnpacker = deEmotet(gui=gui, debug=debug_log)
    unpacking_result = EmotetUnpacker.unpack_file(filename)
    
    if EmotetUnpacker.unpacked and unpacking_result:
        print_metadata(unpacking_result, filename, frmt, verbose=verbose)
    else:
        log_error("[!] Error. File: {0} For more info execute it again with --debug-log option.".format(filename))

    if write_results and EmotetUnpacker.unpacked:
        EmotetUnpacker.write()


def usage():
    usage_message = []
    usage_message.append("usage: %prog [options] arg                               ")
    usage_message.append("  _____ __  __  ___ _____ _____ _____                    ")
    usage_message.append(" | ____|  \\/  |/ _ \\_   _| ____|_   _|                 ")
    usage_message.append(" |  _| | |\\/| | | | || | |  _|   | |                    ")
    usage_message.append(" | |___| |  | | |_| || | | |___  | |                     ")
    usage_message.append(" |_____|_|  |_|\\___/ |_| |_____| |_|_____ ____          ")
    usage_message.append(" | | | | \\ | |  _ \\ / \\  / ___| |/ / ____|  _ \\      ")
    usage_message.append(" | | | |  \\| | |_) / _ \\| |   | ' /|  _| | |_) |       ")
    usage_message.append(" | |_| | |\\  |  __/ ___ \\ |___| . \\| |___|  _ <       ")
    usage_message.append("  \\___/|_| \\_|_| /_/_  \\_\\____|_|\\_\\_____|_| \\_\\ ")
    usage_message.append(" | |__  _   _    __| |/ _ \\ / _ \\ _ __| |_             ")
    usage_message.append(" | '_ \\| | | |  / _` | | | | | | | '__| __|             ")
    usage_message.append(" | |_) | |_| | | (_| | |_| | |_| | |  | |_               ")
    usage_message.append(" |_.__/ \\__, |  \\__,_|\\___/ \\___/|_|   \\__|         ")
    usage_message.append("        |___/                                            ")
    usage_message.append("                                                         ")
    usage_message.append("https://github.com/d00rt/emotet_research - 2018          ")
    usage_message.append("                  - @D00RT_RM -                          ")
    usage_message.append("                                                         ")
    return '\r\n'.join(usage_message)


def main(samples='', write=True, debug_log=False, verbose=False, frmt="plaintext"):
    if samples == '':
        run_file(filename=samples, debug_log=True, verbose=None, frmt=None, gui=True, write_results=True)
        return

    if not os.path.exists(samples):
        log_error("[!] Error. {0} does not exist.".format(samples))
        return

    if os.path.isdir(samples):
        run_folder(samples, debug_log, verbose, frmt, write_results=write)
    else:
        run_file(samples, debug_log, verbose, frmt, write_results=write)


if __name__ == "__main__":
    parser = OptionParser(usage=usage(), version="emotet unpacker 1.0.0 by d00rt")
    parser.add_option("-v", "--verbose", dest="verbose",
                      help="adds RSA keys and Command and Control servers to the output records", action="store_true", default=False)
    parser.add_option("-e", "--print-errors", dest="errors",
                      help="print to stdout when a file unpacking fails", action="store_true", default=False)
    parser.add_option("-d", "--debug-log", dest="debug_log",
                      help="print to stdout the debug messages", action="store_true", default=False)
    parser.add_option("-w", "--write-output", dest="write_output",
                      help="write the results in the output folder", action="store_true", default=False)
    parser.add_option("-f", "--output-format", dest="output_format",
                      help="output format: ({0}) [default: %default]".format(', '.join(v for v in VALID_OUTPUTS)), type="string", default="plaintext")

    (options, args) = parser.parse_args()
    output_format = options.output_format.lower() if options.output_format.lower() in VALID_OUTPUTS else "plaintext"
    LOG_ERRORS = options.errors

    if len(args) == 1:
        main(args[0], write=options.write_output, debug_log=options.debug_log, verbose=options.verbose, frmt=output_format)

    elif len(args) == 0:
        main()
    else:
        parser.print_help()
