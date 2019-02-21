'''
Dummy GPIO module for testing
'''
BOARD = 1
OUT = 1
IN = 1
BCM = 1
PUD_UP = True
PUD_DOWN = False
LOW = False
HIGH = True

pin_mode = LOW

def setmode(a):
   print(a)
def setup(a, b, pull_up_down=None):
   return True
def output(a, b):
   print(a)
def cleanup():
   print('a')
def setmode(a):
   print(a)
def setwarnings(flag):
   return True
def input(a):
    return pin_mode
def output(a,mode=LOW):
    pin_mode = mode
    print(str(pin_mode))
