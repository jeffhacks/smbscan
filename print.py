class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def print_status(target, color, message, options):
    statusSymbol = "[-]" if color == Colors.WARNING or color == Colors.FAIL else "[+]"
    if target is None:
        status = "%1s%2s %3s" % (color, statusSymbol, message)
    else:
        status = "%1s%2s %3s (%4s): %5s" % (
            color,
            statusSymbol,
            target.ip,
            target.name,
            message,
        )

    print(status)
    logFile = open(options.outputLogFileName, "a")
    logFile.write(status + "\r\n")
    logFile.close()
