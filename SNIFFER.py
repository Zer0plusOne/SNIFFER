import psutil
from scapy.all import sniff, conf, IP
from datetime import datetime
import threading
import time
import os
import socket
import platform

# Reset
RESTART='\033[0m'        # No Color (reset to default)

# Regular Colors
B='\033[0;30m'  # Black
R='\033[0;31m'    # Red
G='\033[0;32m'  # Green
Y='\033[0;33m' # Yellow
B='\033[0;34m'   # Blue
P='\033[0;35m' # Purple
C='\033[0;36m'   # Cyan
W='\033[0;37m'  # White

IP = "127.0.0.1" # Temporal LocalHost

banner01='''\033[33m
 /$$        /$$$$$$   /$$$$$$  /$$$$$$ /$$   /$$
| $$       /$$__  $$ /$$__  $$|_  $$_/| $$$ | $$
| $$      | $$  \ $$| $$  \__/  | $$  | $$$$| $$
| $$      | $$  | $$| $$ /$$$$  | $$  | $$ $$ $$
| $$      | $$  | $$| $$|_  $$  | $$  | $$  $$$$
| $$      | $$  | $$| $$  \ $$  | $$  | $$\  $$$
| $$$$$$$$|  $$$$$$/|  $$$$$$/ /$$$$$$| $$ \  $$
|________/ \______/  \______/ |______/|__/  \__/\033[97m'''


banner02='''\033[33m                                                                                                                                                                         
                          ██████          ██████                                        
                        ██▓▓▓▓▓▓██████████▓▓▓▓▓▓██                                      
                        ██▓▓▓▓██          ██▓▓▓▓██                                      
                        ██▓▓████    ▓▓▓▓▓▓████▓▓██                                      
                          ██  ██  ██▓▓██▓▓██  ██                                        
                              ██    ▓▓▓▓▓▓██                                            
                            ██              ██                                          
                            ██    ██████    ██                                          
                            ██    ██████    ██                                          
                            ██              ██        ████                              
                              ██    ██    ██  ██      ██▓▓██                            
                                ████░░████    ▓▓██      ██▓▓██                          
                                  ██░░██      ▓▓▓▓██      ██  ██                        
                                  ██░░██      ▓▓▓▓▓▓██    ██  ██                        
                                    ████  ██  ██▓▓▓▓▓▓████    ██                        
                                      ██  ██  ██              ██                        
                                      ██  ██  ██              ██                        
                                      ██  ██  ██        ██    ██                        
                                    ██    ██    ██    ██      ██                        
                                    ████████████████████████████\033[97m

                                    SNIFFER by Zer0                 
                        Github: https://github.com/Zer0plusOne/
\033[97m

'''

banner03='''\033[33m
⠀⠀⠀⢠⣾⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣰⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢰⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣄⣀⣀⣤⣤⣶⣾⣿⣿⣿⡷
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀
⣿⣿⣿⡇⠀⡾⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁ 
⣿⣿⣿⣧⡀⠁⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠉⢹⠉⠙⣿⣿⣿⣿⣿ Entry SNIFF
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣀⠀⣀⣼⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠀⠤⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⠿⠋⢃⠈⠢⡁⠒⠄⡀⠈⠁⠀⠀⠀⠀⠀⠀⠀
⣿⣿⠟⠁⠀⠀⠈⠉⠉⠁⠀⠀⠀⠀⠈⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
\033[97m'''

banner04='''\033[33m

⠀⢀⣠⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣶⡾⠿⠿⠿⠿⢷⣶⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⣿⡟⠛⠛⠛⠻⠿⠿⢿⣶⣶⣦⣤⣤⣀⣀⡀⣀⣴⣾⡿⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠻⢿⣷⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⡀
⠀⠻⣿⣦⡀⠀⠉⠓⠶⢦⣄⣀⠉⠉⠛⠛⠻⠿⠟⠋⠁⠀⠀⠀⣤⡀⠀⠀⢠⠀⠀⠀⣠⠀⠀⠀⠀⠈⠙⠻⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠛⠛⢻⣿
⠀⠀⠈⠻⣿⣦⠀⠀⠀⠀⠈⠙⠻⢷⣶⣤⡀⠀⠀⠀⠀⢀⣀⡀⠀⠙⢷⡀⠸⡇⠀⣰⠇⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣶⡶⠶⠶⠒⠂⠀⠀⣠⣾⠟
⠀⠀⠀⠀⠈⢿⣷⡀⠀⠀⠀⠀⠀⠀⠈⢻⣿⡄⣠⣴⣿⣯⣭⣽⣷⣆⠀⠁⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣦⡀⠀⣠⣾⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⣠⣾⡟⠁⠀
⠀⠀⠀⠀⠀⠈⢻⣷⣄⠀⠀⠀⠀⠀⠀⠀⣿⡗⢻⣿⣧⣽⣿⣿⣿⣧⠀⠀⣀⣀⠀⢠⣿⣧⣼⣿⣿⣿⣿⠗⠰⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⡿⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⢿⣶⣄⡀⠀⠀⠀⠀⠸⠃⠈⠻⣿⣿⣿⣿⣿⡿⠃⠾⣥⡬⠗⠸⣿⣿⣿⣿⣿⡿⠛⠀⢀⡟⠀⠀⠀⠀⠀⠀⣀⣠⣾⡿⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣷⣶⣤⣤⣄⣰⣄⠀⠀⠉⠉⠉⠁⠀⢀⣀⣠⣄⣀⡀⠀⠉⠉⠉⠀⠀⢀⣠⣾⣥⣤⣤⣤⣶⣶⡿⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⢻⣿⠛⢿⣷⣦⣤⣴⣶⣶⣦⣤⣤⣤⣤⣬⣥⡴⠶⠾⠿⠿⠿⠿⠛⢛⣿⣿⣿⣯⡉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣧⡀⠈⠉⠀⠈⠁⣾⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣿⠟⠉⣹⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣸⣿⣿⣦⣀⠀⠀⠀⢻⡀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⣿⠋⣿⠛⠃⠀⣈⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡿⢿⡀⠈⢹⡿⠶⣶⣼⡇⠀⢀⣀⣀⣤⣴⣾⠟⠋⣡⣿⡟⠀⢻⣶⠶⣿⣿⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣷⡈⢿⣦⣸⠇⢀⡿⠿⠿⡿⠿⠿⣿⠛⠋⠁⠀⣴⠟⣿⣧⡀⠈⢁⣰⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⢻⣦⣈⣽⣀⣾⠃⠀⢸⡇⠀⢸⡇⠀⢀⣠⡾⠋⢰⣿⣿⣿⣿⡿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠿⢿⣿⣿⡟⠛⠃⠀⠀⣾⠀⠀⢸⡇⠐⠿⠋⠀⠀⣿⢻⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠁⢀⡴⠋⠀⣿⠀⠀⢸⠇⠀⠀⠀⠀⠀⠁⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡿⠟⠋⠀⠀⠀⣿⠀⠀⣸⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣁⣀⠀⠀⠀⠀⣿⡀⠀⣿⠀⠀⠀⠀⠀⠀⢀⣈⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
\033[97m'''

banner05 = '''\033[33m
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⢻⠋⡏⢛⢹⢹⢦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⠤⠤⠤⠤⣄⣀⣀⠀⠀⢸⣿⢸⣀⡇⢸⣾⢸⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠒⣮⣿⠛⠉⠉⠉⠉⢻⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣶⠟⣩⣿⣶⢰⣖⠒⣶⣼⣀⣀⣠⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢺⠀⠀⠀⠀⠀⠀⣴⣖⣲⣦⠤⣿⣿⡞⠁⠙⠛⠛⢻⡿⠁⡼⠋⢀⣈⡬⠶⠛⠋⠉⠉⠉⠉⠉⠉⢉⣩⠽⠛⣛⣽⠿⣟⣛⣛⣛⡛⠲⢤⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣠⠤⣤⣀⡈⣇⠀⠀⠀⠀⢸⣿⣿⠶⠾⣿⡿⠋⢹⠀⠀⠀⣠⡏⢀⣞⡵⢞⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⣠⠖⠋⣠⢶⣻⠵⡞⣏⠁⠀⠀⠀⠉⠙⠲⣌⡑⢦⡀⠀⠀
⠀⠀⠀⣼⢿⠵⢶⣼⣷⠛⠛⣧⣄⠀⠀⢸⣇⣿⣗⣊⣿⠖⠀⢸⠀⢶⢯⣭⠟⢋⡞⢠⠟⠀⠀⠀⠀⠀⠀⠀⠀⢀⡞⠁⣠⠞⡵⢻⡁⠀⢹⡼⡄⠀⠀⠀⠀⠀⠀⠀⠙⢦⡹⣄⠀
⠀⠀⠀⣿⢸⠀⢾⠁⠈⣳⠞⢛⣿⣟⠶⣿⣿⣻⠿⢽⣿⣦⣀⡼⠀⢸⠶⡇⠀⢸⠀⣼⠀⠀⠀⠀⠀⠀⠀⠀⣠⠟⢀⡜⢡⡞⠁⠀⡇⠀⠀⡇⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⡹⡄
⠀⠀⠀⠙⠛⠒⢚⣷⠞⣡⢞⡉⠀⠹⣿⣮⠙⣿⠯⠟⠉⢹⡿⣤⣀⠸⡶⣧⣀⡸⡄⢹⠀⠀⠀⠀⠀⠀⠀⢠⡟⠀⡼⢠⠏⠀⠀⠀⣷⠀⠀⡇⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢃⢻
⠀⢀⣤⠶⢶⣴⠋⣠⢾⡇⠹⣷⣄⠀⠉⠻⣷⡼⣳⣤⣴⣿⣷⡇⢨⣽⣿⣿⠿⣝⣿⣾⣆⠀⠀⠀⠀⠀⠀⢸⠁⠀⡇⡞⠀⠀⠀⢰⠃⠀⢸⢳⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢸
⠀⡸⠹⢾⣖⣛⣿⣅⠀⢧⠀⠈⢻⣧⡀⠀⠘⠻⣟⣻⣿⣿⣿⣿⣿⣿⣿⣿⣦⣬⡿⣿⣿⣦⡀⠀⠀⠀⠀⠘⡆⠀⡇⣇⠀⠀⣠⠋⠀⢠⢏⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢸
⣶⠃⠀⠈⠋⢻⢴⣗⣻⣮⣷⡀⠀⢹⣟⣦⡄⠀⠈⠛⠉⡹⠉⠈⠓⢿⡿⣿⣿⣿⠷⣄⣹⡆⠙⠲⣄⡀⠀⠀⢿⠀⢧⠸⡶⠚⠁⢀⡴⢣⠞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⢸
⠛⢦⡀⠀⠀⠀⢸⠋⠀⠀⢈⡿⡄⢸⣺⡀⠀⠀⠀⠀⢠⡇⡾⣦⡀⠀⠉⢿⣿⠻⣷⣮⠟⢁⣀⣀⣨⣿⣷⣤⡈⢧⠈⣇⠳⣤⠖⣩⠴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢁⠇
⠀⠀⠙⢦⡀⠀⡏⠀⠀⠀⡼⠀⠙⣎⠙⣿⣾⣷⡀⠀⠘⢧⢿⣻⡇⢠⣄⠘⠿⠿⠻⠿⣼⡟⢷⣿⣿⣾⠯⠿⠋⠛⠧⣈⢦⡙⣏⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣡⠊⠀
⠀⠀⠀⠀⠈⠻⠥⠤⠤⠼⠁⠀⠀⠘⢿⣿⡿⣏⣹⣆⠀⠀⠻⣍⠀⢸⣏⠳⡄⠀⠀⠀⠀⠑⢤⣿⣙⣟⣄⠀⠀⢠⡤⠬⠿⢿⣌⡓⢦⣄⡀⠀⠀⠀⠀⠀⠀⠀⣀⠴⣣⠞⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡄⠈⢠⡾⣷⡀⠀⠈⠳⣜⢟⣾⠀⢰⣄⡀⠀⣴⣾⢿⣽⡿⣞⣆⠀⠀⢻⡋⠉⠙⢧⢻⡳⢦⣉⡑⠲⠶⠶⠶⢒⣫⠵⠛⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡇⠀⠀⠳⣝⢿⣦⠀⠀⠈⠳⣍⠀⣞⡇⢹⣶⡏⡇⠀⠙⢿⣹⣜⢦⠀⠀⠳⣄⣀⣬⣷⣷⡄⢳⡌⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣧⠀⠀⠀⠈⢦⡙⣷⠀⠀⠀⠈⠳⣝⠓⣸⢠⢇⡇⠀⠀⠀⠀⠹⣎⢧⠀⠀⠻⣄⣀⣀⣹⡿⡄⠹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣆⠀⠀⠀⠀⢻⠃⠀⠀⠀⠀⠀⠈⠣⡍⢸⢸⠀⠀⠀⠀⠀⠀⠘⣆⢣⡀⠀⠙⣧⠴⠛⢣⠘⣄⠙⣆ EXIT SNIFF
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠘⣆⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣼⡀⠀⠀⠀⠀⠀⢀⡼⣶⠗⠦⡄⠘⣆⠀⠀⣳⣸⡆⠘⣦⠀⣀⣀⣀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠘⣦⠀⠀⠹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣄⠀⠀⠀⢀⡏⢀⠘⡆⠀⠹⣶⢮⡉⠉⠀⠀⠀⠀⠈⢯⠉⠙⣎⢻⡉⠑⢦⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⢸⠋⢧⠀⠀⠹⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢦⡀⠀⢸⢸⠋⡇⣷⠀⠀⣏⡇⣷⠤⣤⡤⠤⠤⠤⢤⡇⠀⠸⡄⢇⠀⠸⡄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⢸⠀⠈⣧⠀⠀⢹⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣄⠈⡞⠦⠇⡿⠀⠀⡿⡇⣹⣶⣾⡷⠖⠲⣶⣟⠀⠀⠀⡇⢸⠀⢠⠇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡇⣸⠀⠀⡼⢳⡀⠈⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢦⡻⣄⣠⡇⣀⡴⠃⡇⢻⠀⠀⠳⣤⡤⠇⠈⢦⡀⠀⡇⢸⣧⠞⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⠀⠀⠀⡇⠀⢳⡀⢷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣄⠉⠉⠁⡀⠀⡇⢈⣀⣁⡀⢉⣀⣉⣉⣉⣷⡀⡇⢸⡇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡇⠀⠀⡇⠀⠀⣿⡜⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢦⡀⠀⠙⢦⡇⠘⠒⠒⠒⠒⠒⠒⠒⠒⠺⠟⠃⢸⣇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡀⢰⠇⠀⠀⢸⠻⡜⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠱⣄⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠛⠛⠛⠉⠉⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠉⠀⠀⠀⢸⠂⠙⡎⠷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⣀⣀⣀⡈⠂
\033[97m'''

def get_ip_address():
    system = platform.system()
    
    if system == "Windows":
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
    else:
        # For Linux, macOS, etc.
        try:
            # Try to use the preferred method of obtaining the IP address
            ip_address = socket.gethostbyname(socket.gethostname())
            if ip_address.startswith("127."):
                # In case of localhost address, use an alternative method
                ip_address = socket.gethostbyname(socket.getfqdn())
        except socket.gaierror:
            ip_address = "Unable to get IP address"
    
    return ip_address

IP_ADDRESS = get_ip_address() # New ip address

# Funcion para obtener el nombre del proceso correspondiente al PID en el sistema
def get_process_name(pid):
    try:
        return psutil.Process(pid).name()
    except psutil.NoSuchProcess:
        return "Unknown"

def packet_callback(packet):
    # Recojo la informacion del protocolo y el puerto
    proto = packet.getlayer(IP).name if packet.haslayer(IP) else "N/A"
    port = packet.sport if hasattr(packet, 'sport') else 'N/A'
    # Recojo el tamaño del paquete
    size = len(packet)
    # Formato del timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # Recojo el PID del proceso que envió el paquete
    pid = packet.payload.pid if hasattr(packet.payload, 'pid') else None
    # Recojo el nombre del proceso correspondiente al PID en el sistema
    process_name = get_process_name(pid) if pid else "Unidentified"

    # Imprimo la informacion
    log_entry = f"\033[0;33m{timestamp}\033[0m | \033[0;36m{process_name}\033[0m | \033[0;32m{proto}\033[0m | {port}\033[0m | \033[0;31m{size}\033[0m bytes"
    print(log_entry)

    time.sleep(0.1)

def start_sniffing(duration=None):
    conf.L3socket = conf.L3socket  # Configurar el socket L3
    if duration:
        sniff(prn=packet_callback, timeout=duration, filter="ip", store=0)
    else:
        sniff(prn=packet_callback, filter="ip", store=0)

def start_sniffing_outbound(duration=None):
    conf.L3socket = conf.L3socket  # Configurar el socket L3
    if duration:
        sniff(prn=packet_callback, timeout=duration, filter="ip and src host " + IP_ADDRESS, store=0)
    else:
        sniff(prn=packet_callback, filter="ip and src host " + IP_ADDRESS, store=0)

def menu_entry():
    os.system("cls" if os.name == "nt" else "clear")
    print(banner03)
    print("1. Temporal SNIFF (5 minutes)")
    print("2. Perpetual Sniff (Permantent: Ctrl+C to stop)")
    print("3. Exit to elections")
    choice = input("SELECT: ")
    if choice == "1":
        os.system("cls" if os.name == "nt" else "clear")
        print("Temporal SNIFF [5 minutes]")
        print("-"*64)
        time.sleep(2)
        start_sniffing(5 * 60)
    elif choice == "2":
        os.system("cls" if os.name == "nt" else "clear")
        print("Perpetual Sniff [Permantent: Ctrl+C to stop]")
        print("-"*64)
        time.sleep(2)
        start_sniffing()
        login()
    elif choice == "3":
        print("exiting...")
        time.sleep(2)
        os.system("cls" if os.name == "nt" else "clear")
        elections()

def menu_outbound():
    os.system("cls" if os.name == "nt" else "clear")
    print(banner05)
    print("X. Insert in this option the IP from your Machine (get the IP from the HELP and INFO menu)")
    print("1. Temporal SNIFF (5 minutes)")
    print("2. Perpetual Sniff (Permanent: Ctrl+C to stop)")
    print("3. Exit to elections")
    choice = input("SELECT: ")
    if choice == "1":
        os.system("cls" if os.name == "nt" else "clear")
        print("Temporal SNIFF [5 minutes]")
        print("-" * 64)
        time.sleep(2)
        start_sniffing_outbound(5 * 60)
    elif choice == "2":
        os.system("cls" if os.name == "nt" else "clear")
        print("Perpetual Sniff [Permanent: Ctrl+C to stop]")
        print("-" * 64)
        time.sleep(2)
        start_sniffing_outbound()
    elif choice == "3":
        print("exiting...")
        time.sleep(2)
        os.system("cls" if os.name == "nt" else "clear")
        elections()
    elif choice == "X":
        print("Insert the IP below")
        global IP_ADDRESS
        IP_ADDRESS = input("IP: ")
        print("\033[0;32m IP saved Successfully \033[0m" + IP_ADDRESS)
        time.sleep(2)
        os.system("cls" if os.name == "nt" else "clear")
        menu_outbound()

def help_print():
    print(banner04)
    print("="*64)
    print("Attention, this tool is for educational purposes only!")
    print("You are using it at your own risk!")
    print("="*64)
    print("All the data will be shown to you in the next format:")
    print("")
    print("\033[0;33mTimestamp\033[0m | \033[0;36mProcess Name\033[0m | \033[0;32mProtocol\033[0m | \033[0;31mPort\033[0m | \033[0;34mSize\033[0m bytes")
    print("")
    print("1 || The timestamp is the time when the packet was captured")
    print("2 || The process name is the name of the process that captured the packet")
    print("3 || The protocol is the protocol used by the packet (TCP, UDP, ICMP)")
    print("4 || The port is the port used by the packet")
    print("5 || The size is the size of the packet in bytes")
    print("")
    print("-"*64)
    print("You are currently using the version:")
    print("\033[0;33mVersion: 1.0.1\033[0m")
    print("IP from this machine: "+ IP_ADDRESS )
    print("="*64)
    print("Type [R] to return to the menu or [Q] to quit")
    select = input("SELECT: ")
    if select == "R":
        print("Loading menu...")
        time.sleep(1)
        os.system("cls" if os.name == "nt" else "clear")
        elections()
    elif select == "Q":
        print("exiting...")
        time.sleep(2)
        os.system("cls" if os.name == "nt" else "clear")
        exit()
    else:
        print("Invalid option, realoading ...")
        time.sleep(2)
        os.system("cls" if os.name == "nt" else "clear")
        help_print()

def elections():
    print(banner02)
    print("1. HELP & INFO")
    print("2. Entry SNIFF")
    print("3. Exit SNIFF")
    print("4. EXIT to login")
    print("5. EXIT PROGRAM")
    choice = input("SELECT: ")
    if choice == "1":
        print("Loading menu...")
        time.sleep(1)
        os.system("cls" if os.name == "nt" else "clear")
        help_print()
    elif choice == "2":
        print("Loading menu...")
        time.sleep(2)
        menu_entry()
    elif choice == "3":
        print("Loading menu...")
        time.sleep(2)
        menu_outbound()
    elif choice == "4":
        print("Logging off...")
        time.sleep(2)
        os.system("cls" if os.name == "nt" else "clear")
        login()
    elif choice == "5":
        print("exiting...")
        time.sleep(2)
        os.system("cls" if os.name == "nt" else "clear")
        exit()

def login():
    os.system("cls" if os.name == "nt" else "clear")
    print(banner01)
    print("")
    user = input("User: ")
    password = input("Password: ")
    
    if user == "Zer0" and password == "plusone":
        os.system("cls" if os.name == "nt" else "clear")
        print("")
        print("\033[0;32mLogin successful.\033[97m")
        time.sleep(2)
        pass
    else:
        os.system("cls" if os.name == "nt" else "clear")
        print("")
        print("\033[0;31mCredenciales incorrectas. Por favor, inténtalo de nuevo.\033[97m")
        time.sleep(2)
        os.system("cls" if os.name == "nt" else "clear")
        login()

def menu():
    login()
    os.system("cls" if os.name == "nt" else "clear")
    elections()

menu()
