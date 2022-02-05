#!/usr/bin/env python3

### HELPER FUNCTIONS (IF NECESSARY) ###
 
### MAIN FUNCTION ###
def main():
  file = sys.argv[1]
  with open(file) as f:
    log_output(f)
  
### DUNDER CHECK ###
if __name__ == "__main__":
  main()
