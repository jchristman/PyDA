# app.py settings
QUEUE_PROCESS_AMT = 20
QUEUE_PROCESS_DELAY = 10

# guielements.py settings
START = '1.0'
LINES_BUFFER_SIZE = 1000
LINES_BUFFER_LOW_CUTOFF = 0.40
LINES_BUFFER_HIGH_CUTOFF = 0.60
MOVETO_YVIEW = 0.5
MAX_LINES_JUMP = 40
MAX_JUMP_CUTOFF = float(MAX_LINES_JUMP) / LINES_BUFFER_SIZE
