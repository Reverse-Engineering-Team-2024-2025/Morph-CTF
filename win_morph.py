import os, logging, subprocess, time, sys, string, random
import r2pipe
from colorama import Fore, init




BIN_PATH = "./morph"
TEMP_FLAG = ""
TRUE_FLAG = ""



def setup_loggers():
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)

    # Logger principale
    logger = logging.getLogger("debugger")
    logger.setLevel(logging.DEBUG)  # Cattura tutto

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # FileHandler - INFO (svuota il file ogni volta che lo script è eseguito)
    info_handler = logging.FileHandler(os.path.join(log_dir, "info.log"), mode='w')
    info_handler.setLevel(logging.INFO)
    info_handler.setFormatter(formatter)

    # FileHandler - DEBUG (svuota il file ogni volta che lo script è eseguito)
    debug_handler = logging.FileHandler(os.path.join(log_dir, "debug.log"), mode='w')
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(formatter)

    # FileHandler - ERROR (svuota il file ogni volta che lo script è eseguito)
    error_handler = logging.FileHandler(os.path.join(log_dir, "error.log"), mode='w')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)

    # StreamHandler - INFO in console
    console_info_handler = logging.StreamHandler(sys.stdout)
    console_info_handler.setLevel(logging.INFO)
    console_info_handler.setFormatter(formatter)

    class InfoFilter(logging.Filter):
        def filter(self, record):
            return record.levelno == logging.INFO
    console_info_handler.addFilter(InfoFilter())

    # StreamHandler - ERROR in console
    console_error_handler = logging.StreamHandler(sys.stderr)
    console_error_handler.setLevel(logging.ERROR)
    console_error_handler.setFormatter(formatter)

    class ErrorFilter(logging.Filter):
        def filter(self, record):
            return record.levelno == logging.ERROR
    console_error_handler.addFilter(ErrorFilter())

    # Aggiungi gli handler al logger
    logger.addHandler(info_handler)
    logger.addHandler(debug_handler)
    logger.addHandler(error_handler)
    logger.addHandler(console_info_handler)
    logger.addHandler(console_error_handler)

    return logger

# Logger globale
logger = setup_loggers()







def init_debug(bin_path, temp_flag):
    """ 
    Init Debugger Instance 
    ood - stands for open object debug with input flag 
    """
    r2 = r2pipe.open(bin_path)
    pid_process_ood = r2.cmd("ood %s" % temp_flag)
    
    if pid_process_ood != 0 :
        logger.info(f"[*] Open Radare2 with dynamic debugging ! with PID : {pid_process_ood}")
        return r2
    else :
        logger.error("[*] The ID of the process is 0 and is an error")
        exit(1)









# Add Comment 
def disable_aslr():
    logger.info("[*] Disable ASLR...")
    try:
        subprocess.run(["sudo", "tee", "/proc/sys/kernel/randomize_va_space"], input=b"0\n", check=True)

    except subprocess.CalledProcessError:
        
        logger.error("[!] Errore nel disabilitare ASLR. Richiede sudo.")
        exit(1)




def retrieve_breakpoint_flag_string(r2, target_substring="What are you waiting for, go submit that flag!"):
    function_analysis = r2.cmd("pdf @ main")

    lines = function_analysis.strip().splitlines()
    parsed_lines = [line.strip() for line in lines if line.strip()]

    breakpoint_addresses = []

    for i, line in enumerate(parsed_lines, 1):
        if target_substring in line:
            address = next((token for token in line.split() if token.startswith("0x")), None)
            if address:
                logger.debug(f"{i:03}: {line}")
                logger.debug(f" → Imposto breakpoint a: {address}\n")
                r2.cmd(f"db {address}")
                breakpoint_addresses.append(address)

    if not breakpoint_addresses:
        logger.debug("Nessun indirizzo trovato con la stringa target.")
    else:
        logger.debug("Breakpoints impostati agli indirizzi:")
        for addr in breakpoint_addresses:
            logger.debug(f" • {addr}")

    return breakpoint_addresses




# finds all the address that has the "call rax" function 
def retrieve_break_point_call_rax(r2):
    function_analyze_strings = r2.cmd("pdf @ main")
    logger.debug("Linee di function_analyze_strings : \n")

    lines = function_analyze_strings.strip().splitlines()

    # Rimuoviamo righe vuote e le formattiamo
    parsed_lines = [line.strip() for line in lines if line.strip()]

    breakpoint_addresses = []

    for i, line in enumerate(parsed_lines, 1):
        if "call rax" in line:
            address = next((token for token in line.split() if token.startswith("0x")), None)
            if address:
                logger.debug(f"{i:03}: {line}")
                logger.debug(f" → Imposto breakpoint a: {address}\n")
                r2.cmd(f"db {address}")
                breakpoint_addresses.append(address)

    logger.debug("Breakpoints impostati agli indirizzi:")
    for addr in breakpoint_addresses:
        logger.debug(f" • {addr}")

    return breakpoint_addresses






# Extract cmp value 
def extract_value_cmp(disasm_block):
    valore_cmp = None
    lines = disasm_block.strip().splitlines()

    for line in lines:
        line = line.strip()
        if "cmp al," in line:
            parts = line.split("cmp al,")
            if len(parts) > 1:
                valore_cmp = parts[1].strip()
                valore_pulito = valore_cmp.split(";")[0].strip()  # Rimuove il commento

    if valore_pulito:
        logger.info(f"[**] value to compare: {valore_pulito}")
    return valore_pulito













# check if the rip register is in the  
def find_flags( r2, break_point_addresses, what_are_you_waiting_for_point ):


    current_line_address = r2.cmd("dr rip").strip()

    logger.debug(f"Value of rip register : {current_line_address}")

    logger.info("[*] Before check flags ")


    address_init_flag_input = 0

    j = 0

    while(j<23):

        # current line address goes to the break_point 
        r2.cmd("dc") # continue to the protocol
        time.sleep(0.2) # wait 0.1 seconds 
        current_line_address = r2.cmd("dr rip").strip()

        

        logger.debug(f"Valore di current_line_address : {current_line_address}")

        if current_line_address in break_point_addresses:
            
            # Check if is the first or the second break point 

            logger.debug(f"Value of rip register : {current_line_address}")
            
            # if(array[index] !=0 )
            # First Break-Point in the cycle 
            if(current_line_address == break_point_addresses[0]):
                
                logger.debug(f"Value of rip register , first break point  : {current_line_address}")
                rdi_register_value = r2.cmd("dr rdi").strip()
                logger.debug(f"Value of RDI register : {rdi_register_value}")
                # In RDI there are the byte of the flag that we want to change 
                # The first iteration RDI point to the first character of the string 
                # In this case we can retreive all the 23° characters of the strings 
                if(j == 0):
                    address_init_flag_input = rdi_register_value

                rax_register_value = r2.cmd("dr rax").strip()
                # From the rax register we can retrieve the other instructions to have always the comparison with the correct character 

                # Extract the other instruction of comparison with the input string 
                assembly_block = r2.cmd(f"pd 4 @ {rax_register_value}")
                logger.debug("\n Lines of assembly blocking \n")
                logger.debug(f"{assembly_block}")

                value_to_change_in_string = extract_value_cmp(assembly_block)
                # Change the value in the string 
                
                # For change one byte of the input string
                # To read this character 
                # p8 1 @ rdi 
                value_of_input_string = r2.cmd(f"p8 1 @ {rdi_register_value}").strip()
                logger.info(f"[*] hexdecimal value of input string : {value_of_input_string}")
                if(value_to_change_in_string != value_of_input_string):
                    # To write the correct character
                    # wx {value_extract} @ rdi
                    r2.cmd(f"wx {value_to_change_in_string} @ {rdi_register_value}")
                    logger.info("\n After Change the character :\n")
                    temp_string_value = r2.cmd(f"ps 23 @ {address_init_flag_input}").strip()
                    logger.info(f"\n {temp_string_value} \n")
                
                # After Change , we can continue with the debugging 
                j=j+1


            
            # if(array[index] == 0)
            # Second Break-Point 
            elif(current_line_address == break_point_addresses[1]):
                logger.debug(f"Value of rip register , first break point  : {current_line_address}")
                rdi_register_value = r2.cmd("dr rdi").strip()
                logger.debug(f"Value of RDI register : {rdi_register_value}")
                rax_register_value = r2.cmd("dr rax").strip()

                # Extract the other instruction of comparison with the input string 
                assembly_block = r2.cmd(f"pd 4 @ {rax_register_value}")
                logger.debug("\n Lines of assembly blocking \n")
                logger.debug(f"{assembly_block}")
                value_to_change_in_string = extract_value_cmp(assembly_block)
                # Change the value in the string 
                
                # For change one byte of the input string
                # To read this character 
                # p8 1 @ rdi 
                value_of_input_string = r2.cmd(f"p8 1 @ {rdi_register_value}").strip()
                logger.info(f"[*] hexdecimal value of input string : {value_of_input_string}")
                if(value_to_change_in_string != value_of_input_string):
                    # To write the correct character
                    # wx {value_extract} @ rdi
                    r2.cmd(f"wx {value_to_change_in_string} @ {rdi_register_value}")
                    logger.info("\n After Change the character :\n")
                    temp_string_value = r2.cmd(f"ps 23 @ {address_init_flag_input}").strip()
                    logger.info(f"\n {temp_string_value} \n")
                
                # After Change , we can continue with the debugging 
                j=j+1
    
    # current line address goes to the break_point 
    r2.cmd("dc") # continue to the protocol
    time.sleep(0.2) # wait 0.1 seconds 
    current_line_address = r2.cmd("dr rip").strip()
    logger.debug(f"Valore di RIP : {current_line_address}")
    if current_line_address in what_are_you_waiting_for_point:
        # The rip is in condition of error or "What are you waiting for, go submit the flag!"            
        # reach the string of "what are you waiting for, go to submit the flag!" 
        # p8 23 @ {address_init_flag} ( save the strings in ASCII ) ps 23 @ rdi
        TEMP_FLAG = r2.cmd(f"ps 23 @ {address_init_flag_input}").strip()
        logger.info(f"[***] Flag to submit to challenge : {TEMP_FLAG}")
        r2.cmd("ds 10")
        time.sleep(0.2)
        return TEMP_FLAG

    


def run_profiling_debug(r2):
    logger.info("[*] First Analysis of the script ...")
    
    # call function to analyze the main
    r2.cmd("aa")

    
    # Continue until the main
    r2.cmd("dcu main") 
    time.sleep(0.1)


    # Remember to Strip the address to recover the main address 
    main_instruction_address = r2.cmd("dr rip").strip() # Delete the \n 

    time.sleep(0.1)
    logger.debug(f"Valore Address : {main_instruction_address}")
    if(main_instruction_address == "0x555555400a76"):
        logger.info("[*] reach main function! ")
        
        # Set breakpoint to the call rax function 
        break_point_functions = retrieve_break_point_call_rax(r2)
        logger.info("[*] Set break point to 'call rax' functions")
        # Retrieve break point of success
        what_are_you_waiting_for_point = retrieve_breakpoint_flag_string(r2)
        logger.info("[*] Set break point to '' functions")

        TEMP_FLAG = find_flags(r2,break_point_functions, what_are_you_waiting_for_point)
        return TEMP_FLAG


    else:
        logger.error("[*] main function not reached !")
        exit(1) 



def input_flag():
    # Caratteri ammessi (alfabeto, numeri, caratteri speciali tranne le virgolette)
    allowed_chars = string.ascii_letters + string.digits + "!?#"

    # Escludi caratteri non stampabili o problematici
    allowed_chars = ''.join(c for c in allowed_chars if c.isprintable() and c != '\x00')

    # Genera la flag
    flag = ''.join(random.choice(allowed_chars) for _ in range(23))
    logger.info(f"[*] Generated flag: {flag}")
    return flag



def run_morph_with_flag(flag):
    try:
        # Esegui il binario "morph" passando la flag
        process = subprocess.Popen(['./morph', flag], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Leggi l'output e l'errore del processo
        stdout, stderr = process.communicate()

        # Decodifica i byte in stringa
        stdout = stdout.decode('utf-8')
        stderr = stderr.decode('utf-8')

        # Controlla se la flag è corretta
        if "What are you waiting for, go submit that flag!" in stdout:
            # Se la flag è corretta, stampa il messaggio di successo
            print(stdout)
            logger.info(f"Successfully executed morph with flag: {flag}")
        else:
            # Se la flag è falsa, stampa l'output
            print(stdout, end="")
            logger.error(f"Invalid flag attempted: {flag}")

        # Se c'è dell'errore, loggalo
        if stderr:
            print(stderr, end="")  # Stampa gli errori
            logger.error(f"Error running morph: {stderr}")

    except Exception as e:
        logger.error(f"An error occurred while running morph: {str(e)}")
        print(f"[!] Error running morph: {str(e)}")






def main():

    # Check if binary not exist
    if not os.path.exists(BIN_PATH):
        logger.error(f"Errore: binario non trovato a {BIN_PATH}")
        return
    
    # Disable the ASLR address 
    disable_aslr()

    # Insert in input the flag 
    TEMP_FLAG = input_flag()

    ############ r2 Debugging ############

    # Init debug
    r2 = init_debug(BIN_PATH, TEMP_FLAG)

    logger.info("[*] init debugger profiling ")

    TRUE_FLAG = run_profiling_debug(r2)

    r2.quit()

    ############ r2 Debugging ############

    logger.info("[***] Check the flag to the morph file ...")

    logger.info("[***] Run moprh file with a false ...")
    # Run the morph file with the flag not true 
    run_morph_with_flag(TEMP_FLAG)


    logger.info("[***] Run moprh with the true flag ...")
    # Run morph file with the flag true
    run_morph_with_flag(TRUE_FLAG)




if __name__ == "__main__":
    main()
