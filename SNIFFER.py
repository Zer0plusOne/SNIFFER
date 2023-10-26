import os
import time
from scapy.all import sniff


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
#funcion de analizar paquetes entrantes en la red y mostrarlos en pantalla

def sniff_entry():
    packets = sniff(filter="tcp", count=100, store=True)
    packets.show()

#funcion de analizar paquetes salientes en la red y mostrarlos en pantalla
def sniff_exiting():
    packets = sniff(filter="tcp", count=100, iface="eth0", store=False)
    for packet in packets:
        packet.show()

#menu de login
def login():
    print(banner01)
    print("Introduce tu nombre de usuario:")
    user = input()
    print("Introduce tu contraseña:")
    password = input()
    if user == "admin" and password == "admin":
        print("Login correcto")
        time.sleep(5)
        menu()
    else:
        print("Login incorrecto")
        time.sleep(5)
        os.system("cls")
        login()
# Menu
def menu():
    os.system("cls")
    print(banner02)
# caja de elecciones
def elections():
    print("1. Entry SNIFF")
    print("2. Exit SNIFF")
    print("3. EXIT to login")
    print("4. EXIT PROGRAM")
    choice = input("SELECT: ")
    if choice == "1":
        print("Entry SNIFF selected... !WAIT TILL IT LOADS!")
        time.sleep(5)
        sniff_entry()
        print("\033[36m============================================================== \033[97m")
        time.sleep(5)
        elections()
    elif choice == "2":
        print("Exiting SNIFF selected !WAIT TILL IT LOADS!")
        time.sleep(5)
        sniff_exiting()
        elections()
    elif choice == "3":
        print("exiting...")
        time.sleep(5)
        os.system("cls")
        login()
    elif choice == "4":
        print("exiting...")
        time.sleep(5)
        os.system("cls")
        exit()


login()
menu()
elections()