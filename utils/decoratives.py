import sys
import time
import itertools
import threading

class SpinnerThread(threading.Thread):
    def __init__(self, message="Processing"):
        super().__init__()
        self.daemon = True
        self.running = True
        self.message = message
        
    def run(self):
        spinner = itertools.cycle(['[/]', '[|]', '[\\]', '[-]'])
        while self.running:
            # Save position, move up 1 line, print spinner, restore position
            sys.stdout.write('\033[s')  # Save cursor position
            sys.stdout.write(f'\033[1A\r{self.message} {next(spinner)}')  # Move up 1 line and print
            sys.stdout.write('\033[K')  # Clear rest of line
            sys.stdout.write('\033[u')  # Restore cursor position
            sys.stdout.flush()
            time.sleep(0.075)
    
    def stop(self):
        self.running = False
        sys.stdout.write('\033[1A\r')  # Move up 1 line
        sys.stdout.write(' ' * 70)  # Clear spinner line
        sys.stdout.write('\r\033[1B')  # Return to start and move down
        sys.stdout.flush()


def progress_bar(total, prefix='', suffix='', length=50):
    def print_progress(iteration):
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = '█' * filled_length + '-' * (length - filled_length)
        sys.stdout.write(f'\r{prefix} |{bar}| {percent}% {suffix}')
        sys.stdout.flush()
        if iteration == total: 
            sys.stdout.write('\n')
    
    return print_progress

# Initialize once
spinner = None
progress = None
initialized = False

def decor_init(total_ports):
    """Initialize spinner and progress bar"""
    global spinner, progress, initialized
    print()
    spinner = SpinnerThread(message="Scanning in progress")
    spinner.start()
    progress = progress_bar(total_ports, prefix='Progress:', length=50)
    initialized = True

def decor_update(scanned):
    # Update progress bar
    global progress
    if progress:
        progress(scanned)

def decor_finish():
    # Stop spinner
    global spinner, initialized
    if spinner:
        spinner.stop()
    initialized = False

def decor(total_ports, scanned_ports):
    global initialized
    
    # Only initialize once
    if not initialized:
        decor_init(total_ports)
    
    # Update progress
    decor_update(scanned_ports)
    
    # Finish when complete
    if scanned_ports >= total_ports:
        decor_finish()
for i in range(101):
    decor(100, i)
    time.sleep(0.05)