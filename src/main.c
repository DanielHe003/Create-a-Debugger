// HAVE TO CHECK RUNNING AND STOPPED FOR WAIT FUNCTION


#define _GNU_SOURCE
#define _XOPEN_SOURCE 700
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "string.h"
#include "deet.h"
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <ctype.h>
#include <errno.h>
#include <sys/user.h>
#include <stdint.h>

void endHandler(int signum);
void checkChildFlag();
volatile sig_atomic_t controlCFlag = 0;
#define MAX_CHILDREN 100 // Maximum number of child processes
char *input = NULL;
void exitProg();

char *helpCommand = "Available commands:\n"
                     "help -- Print this help message\n"
                     "quit (<=0 args) -- Quit the program\n"
                     "show (<=1 args) -- Show process info\n"
                     "run (>=1 args) -- Start a process\n"
                     "stop (1 args) -- Stop a running process\n"
                     "cont (1 args) -- Continue a stopped process\n"
                     "release (1 args) -- Stop tracing a process, allowing it to continue normally\n"
                     "wait (1-2 args) -- Wait for a process to enter a specified state or terminate\n"
                     "kill (1 args) -- Forcibly terminate a process\n"
                     "peek (2-3 args) -- Read from the address space of a traced process\n"
                     "poke (3 args) -- Write to the address space of a traced process\n"
                     "bt (1-2 args) -- Show a stack trace for a traced process\n";

int endflag = 0;
int blockFlag = 0;
struct Process {
    int id;
    PSTATE state;
    char traced;
    int argnumber;
    char *arguments[100];
    int exitStatus;
    int changeFlag;
};

// Signal handler function for SIGINT
void endHandler(int signum) {
    log_signal(SIGINT);
    log_signal(SIGCHLD);
    controlCFlag = 1;
}
pid_t pidchild = 0;
volatile sig_atomic_t childFlag = 0;
int childstatus;
struct Process processes[MAX_CHILDREN]; // Array of structs

void sigchld_handler(int signum) {
    log_signal(SIGCHLD);
    childFlag = 1;
    pidchild = waitpid(-1, &childstatus, WNOHANG | WUNTRACED | WCONTINUED);
}

char *line_copy;
int main(int argc, char *argv[]) {

    log_startup();

    for(int i = 0; i < MAX_CHILDREN; i++){
        processes[i].id = 0;
        processes[i].state = PSTATE_NONE;
        processes[i].traced = '\0';
        processes[i].exitStatus = 0;
    }

    // Create a signal set to block
    sigset_t blockSet;
    sigemptyset(&blockSet);
    sigaddset(&blockSet, SIGCHLD);

    int p_flag = 0; // Initialize a flag to 0
    int run_flag = 0;
    // Check each command-line argument for '-p'
    for (int i = 1; i < argc; i++) {  // Start from 1 to skip the program name (argv[0])
        if (strcmp(argv[i], "-p") == 0) {
            p_flag = 1; // Set the flag to 1 if '-p' is found
            break;
        }
    }

    ssize_t read;
    size_t len = 0;
    while (1) {

        if(controlCFlag == 1){
            log_shutdown();
            exit(0);
        }
        //accounts for control + c signal
        struct sigaction sa;
        sa.sa_handler = endHandler;
        sigaction(SIGINT, &sa, NULL);

        struct sigaction child;
        child.sa_handler = sigchld_handler;
        child.sa_flags = SA_RESTART;
        sigemptyset(&child.sa_mask);
        if (sigaction(SIGCHLD, &child, NULL) == -1) {
            perror("Error setting SIGCHLD handler");
            return EXIT_FAILURE;
        }

        for(int i = 0; i < MAX_CHILDREN; i++){
            if(processes[i].id != 0 && run_flag == 1){
                if(processes[i].state == PSTATE_RUNNING){
                    // Suspend the process until SIGCHLD is caught
                    sigset_t mask;
                    sigemptyset(&mask);
                    sigsuspend(&mask);
                    processes[i].state = PSTATE_DEAD;
                }
            } else {
                break;
            }
        }
        
        checkChildFlag();
        log_prompt();
        if(p_flag == 0){ 
            printf("deet> ");
            fflush(stdout);
        }
        if(blockFlag == 1){
            if (sigprocmask(SIG_UNBLOCK, &blockSet, NULL) == -1) {
                log_error(input);
                return 1;
            }
            blockFlag = 0;
        }
        checkChildFlag();

        while ((read = getline(&input, &len, stdin)) == -1) {
            if(errno == EINTR){
                checkChildFlag();
                if(controlCFlag){
                    exitProg();
                }
                log_prompt();
                if(p_flag == 0){ 
                    printf("deet> ");
                }
                fflush(stdout); // Reprint prompt
                }
            else {
                return 0;
            }
        } 
        
        line_copy = (char *)malloc(strlen(input) + 1);

        if (read != -1) {
            // Remove newline character if present
            if (input[read - 1] == '\n') {
                input[read - 1] = '\0';
            }
        }

        strcpy(line_copy, input);
        strcat(line_copy, "\n");
        if(controlCFlag == 1){
            log_shutdown(); 
            exit(0);    
        }

        // Removing trailing newline character
        input[strcspn(input, "\n")] = 0;
        char *token;
        token = strtok(input, " ");
        char *args[50]; // Assuming a maximum of 50 arguments

        //sets arguments into token
        int i = 0;
        int argNumber = 0;
        while (token != NULL) {
            args[i] = token;
            token = strtok(NULL, " ");
            i++;
            argNumber++;
        }
        args[i] = NULL; // Set the last element of the args array to NULL, required by execvp
        
        run_flag = 0;
        // Check each command-line argument for 'run'
        for (int j = 0; j < i; j++) { 
            if (strcmp(args[j], "run") == 0) {
                run_flag = 1; // Set the flag to 1 if '-p' is found
                break;
            }
        }

        // Now args array contains separate arguments
        if (strcmp(input, "quit") == 0) {
            log_input(line_copy);
            exitProg();
        } else if(strcmp(input, "help") == 0){
            log_input(line_copy);
            printf("%s", helpCommand);
        } else if(strcmp(input, "show") == 0){
            int x = 0;
            if(processes[0].id == 0){
                log_input(line_copy);
                log_error(input);
                printf("?\n");
                x = 1;
            }
            if(x == 0){
                log_input(line_copy);
                //there is already processes
                if(args[1] == NULL){
                    //print out all of them
                    for(int i = 0; i < MAX_CHILDREN; i++){
                        if(processes[i].state != PSTATE_NONE){
                            printf("%d\t%d\t%c\t", i, processes[i].id, processes[i].traced);
                            if(processes[i].state == PSTATE_RUNNING) printf("running\t\t");
                            if(processes[i].state == PSTATE_STOPPED) printf("stopped\t\t");
                            if(processes[i].state == PSTATE_DEAD) printf("dead\t0x%d\t",processes[i].exitStatus);
                            for(int j = 1; j < processes[i].argnumber; j++){
                                printf("%s ", processes[i].arguments[j]);
                            }
                            printf("\n");
                        }
                    }

                } else if (args[1] != NULL){
                    int number = atoi(args[1]);
                    int x = 0;
                    for (int i = 0; i < strlen(args[1]); i++) {
                        if(!isdigit(*args[1]+i) || number < 0){
                            log_error(input);
                            printf("?\n");
                            x = 1;
                        }
                    }
                    //print out one
                    if(x == 0){
                        if(processes[number].state != PSTATE_NONE){
                            printf("%d\t%d\t%c\t", number, processes[number].id, processes[number].traced);
                            if(processes[number].state == PSTATE_RUNNING) printf("running\t\t");
                            if(processes[number].state == PSTATE_STOPPED) printf("stopped\t\t");
                            if(processes[number].state == PSTATE_DEAD) printf("dead\t0x%d\t",processes[number].exitStatus);
                            for(int j = 1; j < processes[number].argnumber; j++){
                                printf("%s ", processes[number].arguments[j]);
                            }
                            printf("\n");
                        } else {
                            log_error(input);
                            printf("?\n");
                        }
                    }
                }

            }
        } else if(strcmp(input, "run") == 0){
            log_input(line_copy);
            int x = 0;
            pid_t pid;
            pid = fork();
            if (pid < 0) {
                log_error(input);
                x = 1;
            } else if (pid == 0) { // Child process
                if (dup2(STDERR_FILENO, STDOUT_FILENO) == -1 && x == 0) {
                    log_error(input);
                    x = 1;
                }

                // Execute the command using execvp
                if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1 && x == 0) {
                    log_error(input);
                    x = 1;
                }

                if(x == 0){
                    args[argNumber] = NULL;
                    char *temp[argNumber-1];
                    for(int i = 1; i < argNumber+1; i++) temp[i-1] = args[i]; 
                    usleep(2000);
                    if (execvp(args[1], temp) < 0) {
                        log_error("Execution failed");
                    }
                }
            } else { // Parent process
            
                // change in state
                log_state_change(pid, PSTATE_NONE, PSTATE_RUNNING, 0);

                args[argNumber] = NULL;
                char *temp[argNumber-1];
                for(int i = 1; i < argNumber+1; i++) temp[i-1] = args[i]; 


                //printing of the commands
                for(int i = 0; i < MAX_CHILDREN; i++){
                    if(processes[i].state == PSTATE_NONE || processes[i].state == PSTATE_KILLED){
                        printf("%d\t%d\tT\trunning\t\t", i, pid);
                        for(int j = 0; j < argNumber-1; j++){
                            printf("%s ", temp[j]);
                        }
                        printf("\n");
                        break;
                    }
                }
                for(int i = 0; i < MAX_CHILDREN; i++){
                    if(processes[i].state == PSTATE_NONE || processes[i].state == PSTATE_KILLED){
                        processes[i].id = pid;
                        processes[i].state = PSTATE_RUNNING;
                        processes[i].argnumber = argNumber;
                        processes[i].traced = 'T';
                        for(int j = 1; j < argNumber; j++){
                            processes[i].arguments[j] = malloc(strlen(args[j]) + 1);
                            strcpy(processes[i].arguments[j], args[j]);
                        }
                        break;
                    }
                }
            }
            
        } else if(strcmp(input, "stop") == 0){
            log_input(line_copy);
            if(argNumber > 2 || argNumber == 1){
                log_error(input);
                printf("?\n");
            } else{
                int number = atoi(args[1]);
                //check to see if the process you're trying to kill is actually running
                if((processes[number].state == PSTATE_RUNNING) || number < 0){
                    log_error(input);
                    printf("?\n");
                } else {
                    kill(processes[number].id, SIGSTOP);
                    processes[number].state = PSTATE_STOPPED;
                }
            }
        } else if(strcmp(input, "cont") == 0){
            log_input(line_copy);
            if(argNumber > 2 || argNumber == 1){
                log_error(input);
                printf("?\n");
            } else{
                int number = atoi(args[1]);
                int x = 0;
                for (int i = 0; i < strlen(args[1]); i++) {
                    if(!isdigit(*args[1]+i) || number < 0){
                        log_error(input);
                        printf("?\n");
                        x = 1;
                    }
                }
                if(x == 0) {
                    if(!(processes[number].state == PSTATE_STOPPED)){
                        log_error(input);
                        printf("?\n");
                    } else{
                        log_state_change(processes[number].id, PSTATE_STOPPED, PSTATE_RUNNING, 0);
                        processes[number].state = PSTATE_RUNNING;
                        //printing of the commands
                        printf("%d\t%d\t%c\trunning\t\t", number, processes[number].id, processes[number].traced);
                        for(int j = 1; j < processes[number].argnumber; j++){
                            printf("%s ", processes[number].arguments[j]);
                        }
                        printf("\n");
                        if (sigprocmask(SIG_BLOCK, &blockSet, NULL) == -1) {
                            log_error(input);
                            printf("?\n");
                        } else {
                            blockFlag = 1;
                            ptrace(PTRACE_CONT, processes[number].id, NULL, NULL);
                        }
                    }
                }
            }
            checkChildFlag();
        } else if(strcmp(input, "release") == 0){
            log_input(line_copy);
            if(argNumber > 2 || argNumber == 1){
                log_error(input);
                printf("?\n");
            } else{
                int number = atoi(args[1]);
                int x = 0;
                for (int i = 0; i < strlen(args[1]); i++) {
                    if(!isdigit(*args[1]+i) || number < 0){
                        log_error(input);
                        printf("?\n");
                        x = 1;
                    }
                }
                if(x == 0) {
                    if((processes[number].state == PSTATE_DEAD)){
                        log_error(input);
                        printf("?\n");
                    } else {
                        log_state_change(processes[number].id, processes[number].state, PSTATE_RUNNING, 0);
                        processes[number].state = PSTATE_RUNNING;
                        //printing of the commands
                        processes[number].traced = 'U';
                        printf("%d\t%d\t%c\trunning\t\t", number, processes[number].id, processes[number].traced);
                        for(int j = 1; j < processes[number].argnumber; j++){
                            printf("%s ", processes[number].arguments[j]);
                        }
                        printf("\n");
                        ptrace(PTRACE_DETACH, processes[number].id, NULL, NULL);
                    }
                }
            }
        } else if(strcmp(input, "wait") == 0){
            log_input(line_copy);
            if(argNumber > 3 || argNumber == 1){
                log_error(input);
                printf("?\n");
            } else {
                int number = atoi(args[1]);
                int x = 0;
                for (int i = 0; i < strlen(args[1]); i++) {
                    if(!isdigit(*args[1]+i) || number < 0){
                        log_error(input);
                        printf("?\n");
                        x = 1;
                    }
                }
                if(processes[number].id == 0){
                    log_error(input);
                    printf("?\n");
                    x = 1;
                } else if(args[2] != NULL && x == 0){
                    //waiting for any of these states
                    if(strcmp(args[2], "running") == 0 || strcmp(args[2], "stopping") == 0 ||
                    strcmp(args[2], "stopped") == 0 || strcmp(args[2], "continuing") == 0 ||
                    strcmp(args[2], "killed") == 0 || strcmp(args[2], "dead") == 0){
                        pid_t wpid;
                        int status;
                        if(strcmp(args[2], "running") == 0){
                            do {
                                wpid = waitpid(processes[number].id, &status, WUNTRACED | WCONTINUED);
                                if (wpid == -1) {
                                    log_error(input);
                                    printf("?\n");
                                    log_shutdown();
                                    x = 1;
                                    break;
                                }
                                if(WIFCONTINUED(status)){
                                    log_state_change(processes[number].id, processes[number].state, PSTATE_RUNNING, 0);
                                    processes[number].state = PSTATE_RUNNING;
                                    printf("%d\t%d\t%c\trunning\t\t", number, processes[number].id, processes[number].traced);
                                    //printing of the commands
                                    for(int j = 1; j < processes[number].argnumber; j++){
                                        printf("%s ", processes[number].arguments[j]);
                                    }
                                    printf("\n");
                                    break;
                                }
                            } while (1);
                        } else if (strcmp(args[2], "stopping") == 0 && x == 0){
                            if(processes[number].state == PSTATE_STOPPING){
                            } else{
                                wpid = waitpid(processes[number].id, &status, WUNTRACED);
                            }
                        } else if (strcmp(args[2], "stopped") == 0 && x == 0){
                            if(processes[number].state == PSTATE_STOPPED){
                            } else {
                                do {
                                    wpid = waitpid(processes[number].id, &status, WUNTRACED);
                                    if (wpid == -1) {
                                        log_error(input);
                                        printf("?\n");
                                        x = 1;
                                    }
                                    if(WIFSTOPPED(status) && WIFEXITED(status)){
                                        log_state_change(processes[number].id, processes[number].state, PSTATE_STOPPED, 0);
                                        processes[number].state = PSTATE_STOPPED;
                                        printf("%d\t%d\t%c\tstopped\t\t", number, processes[number].id, processes[number].traced);
                                        //printing of the commands
                                        for(int j = 1; j < processes[number].argnumber; j++){
                                            printf("%s ", processes[number].arguments[j]);
                                        }
                                        printf("\n");
                                        break;
                                    }
                                } while (1);
                            }
                        } else if (strcmp(args[2], "continuing") == 0 && x == 0){
                            if( processes[number].state == PSTATE_CONTINUING){
                            } else {
                                do {
                                    wpid = waitpid(processes[number].id, &status, WCONTINUED);
                                    if (wpid == -1) {
                                        log_error(input);
                                        printf("?\n");
                                        x = 1;
                                    }
                                    if(x == 0){
                                        log_state_change(processes[number].id, processes[number].state, PSTATE_CONTINUING, 0);
                                        processes[number].state = PSTATE_CONTINUING;
                                        printf("%d\t%d\t%c\tcontinuing\t\t", number, processes[number].id, processes[number].traced);
                                        //printing of the commands
                                        for(int j = 1; j < processes[number].argnumber; j++){
                                            printf("%s ", processes[number].arguments[j]);
                                        }
                                        printf("\n");
                                    }
                                } while (!WIFCONTINUED(status));
                            }
                        } else if (strcmp(args[2], "killed") == 0){
                            if(processes[number].state == PSTATE_KILLED){
                            } else {
                                do {
                                    wpid = waitpid(processes[number].id, &status, WNOHANG);
                                    if (wpid == -1) {
                                        log_error(input);
                                        printf("?\n");
                                        x = 1;
                                    }
                                    if (WIFSIGNALED(status) && wpid != 0 && WTERMSIG(status) == SIGKILL && x == 0) {
                                        log_state_change(processes[number].id, processes[number].state, PSTATE_KILLED, 0);
                                        processes[number].state = PSTATE_KILLED;
                                        printf("%d\t%d\t%c\tkilled\t\t", number, processes[number].id, processes[number].traced);
                                        //printing of the commands
                                        for(int j = 1; j < processes[number].argnumber; j++){
                                            printf("%s ", processes[number].arguments[j]);
                                        }
                                        printf("\n");
                                        break;
                                    }
                                } while (1);
                            }
                        } else if (strcmp(args[2], "dead") == 0){
                            if(processes[number].state == PSTATE_DEAD){
                            } else {
                                do {
                                    wpid = waitpid(processes[number].id, &status, WUNTRACED);
                                    if (wpid == -1) {
                                        log_error(input);
                                        printf("?\n");
                                        x = 1;
                                    }
                                    if (WIFEXITED(status) && x == 0) {
                                        processes[number].exitStatus = WEXITSTATUS(status);
                                        log_state_change(processes[number].id, processes[number].state, PSTATE_DEAD,WIFEXITED(status));
                                        processes[number].state = PSTATE_DEAD;
                                        printf("%d\t%d\t%c\tdead\t0x%d\t", number, processes[number].id, processes[number].exitStatus, processes[number].traced);
                                        //printing of the commands
                                        for(int j = 1; j < processes[number].argnumber; j++){
                                            printf("%s ", processes[number].arguments[j]);
                                        }
                                        printf("\n");
                                    }
                                } while (!WIFEXITED(status));
                            }
                        }
                    } else{
                        x = 1;
                    }
                } else {
                    //default state, waiting for dead
                    if(x == 0) {
                        if((processes[number].id == 0)){
                            log_error(input);
                            printf("?\n");
                            x = 1;
                        } else {
                            // Wait for the child process to terminate
                            int status;
                            pid_t terminated_child = waitpid(processes[number].id, &status, 0);
                            if (terminated_child == processes[number].id) {
                                if (WIFEXITED(status)) {
                                    processes[number].exitStatus = WEXITSTATUS(status);
                                    log_state_change(processes[number].id, processes[number].state, PSTATE_DEAD,WIFEXITED(status));
                                    processes[number].state = PSTATE_DEAD;
                                    printf("%d\t%d\t%c\tdead\t0x%d\t", number, processes[number].id, processes[number].traced, processes[number].exitStatus);
                                    //printing of the commands
                                    fflush(stdout);
                                    for(int j = 1; j < processes[number].argnumber; j++){
                                        printf("%s ", processes[number].arguments[j]);
                                    }
                                    printf("\n");
                                }
                            }
                        }
                    }
                }
            }
        } else if(strcmp(input, "kill") == 0){
            log_input(line_copy);
            if(argNumber > 2 || argNumber == 1){
                log_error(input);
                printf("?\n");
            } else{
                int number = atoi(args[1]);
                if(number < 0){
                    log_error(input);
                    printf("?\n");
                }else if((processes[number].state == PSTATE_DEAD)){
                    log_error(input);
                    printf("?\n");
                } else {
                    log_state_change(processes[number].id, processes[number].state, PSTATE_KILLED, 0);
                    // printing of the commands
                    printf("%d\t%d\t%c\tkilled\t", number, processes[number].id,processes[number].traced);
                    if(processes[number].state == PSTATE_DEAD) {
                        printf("0x%x\t",processes[number].exitStatus);
                    } else {
                        printf("\t");
                    }
                    for(int j = 1; j < processes[number].argnumber; j++){
                        printf("%s ", processes[number].arguments[j]);
                    }
                    printf("\n");
                    kill(processes[number].id, SIGKILL);
                    processes[number].state = PSTATE_DEAD;
                    
                }
            }
        } else if(strcmp(input, "peek") == 0){
            void *address;
            log_input(line_copy);
            if(argNumber > 4 || argNumber < 3){
                log_error(input);
                printf("?\n");
            } else if(args[3] == NULL) {
                int number = atoi(args[1]);
                if (sscanf(args[2], "%p", &address) != 1) {
                    log_error(input);
                    printf("?\n");
                } else if(processes[number].id == 0){
                    log_error(input);
                    printf("?\n");
                } else {
                    int x = 0;
                    for (int i = 0; i < strlen(args[1]); i++) {
                        if(!isdigit(*args[1]+i)){
                            log_error(line_copy);
                            printf("?\n");
                            x = 1;
                        }
                    }
                    if(x == 0) {
                        long data = ptrace(PTRACE_PEEKDATA, processes[number].id, address, NULL);
                        if (data == -1 && errno != 0) {
                            log_error(input);
                            printf("?\n");
                        } else {
                            for(int i = strlen(args[2]); i < 16; i++) printf("0");
                            printf("%s\t%lx\n",args[2], data);
                            fflush(stdout); 
                        }
                    }
                }
            } else {
                int number = atoi(args[1]);
                int number2 = atoi(args[3]);
                if (sscanf(args[2], "%p", &address) != 1 || number2 < 0 || number < 0) {
                    log_error(input);
                    printf("?\n");
                } else if(processes[number].id == 0){
                    log_error(input);
                    printf("?\n");
                } else {
                    int x = 0;
                    for (int i = 0; i < strlen(args[1]); i++) {
                        if(!isdigit(*args[1]+i)){
                            log_error(line_copy);
                            printf("?\n");
                            x = 1;
                        }
                    }
                    if(x == 0) {
                        for(int i = 0; i < number2; i++){
                            unsigned long data = ptrace(PTRACE_PEEKDATA, processes[number].id, address, NULL);
                            if (data == -1 && errno != 0) {
                                perror("ptrace: ");
                                log_error(input);
                                printf("?\n");
                            } else {
                                for(int i = strlen(args[2]); i < 16; i++) printf("0");
                                printf("%s\t%lx\n",args[2], data);
                                fflush(stdout); 
                            }
                            address += 8;
                        }
                    }
                }
            }
        } else if(strcmp(input, "poke") == 0){
            unsigned long long address;
            log_input(line_copy);
            if(argNumber != 4){
                log_error(input);
                printf("?\n");
            } else {
                int number = atoi(args[1]);
                unsigned long long data = strtoull(args[3], NULL, 16);
                address = strtoull(args[2], NULL, 16);
                if (number < 0  || errno == ERANGE) {
                    log_error(input);
                    printf("?\n");
                } else if(processes[number].id == 0){
                    log_error(input);
                    printf("?\n");
                } else {
                    int x = 0;
                    for (int i = 0; i < strlen(args[1]); i++) {
                        if(!isdigit(*args[1]+i)){
                            log_error(line_copy);
                            printf("?\n");
                            x = 1;
                        }
                    }
                    if(x == 0) {
                        if (ptrace(PTRACE_POKEDATA, processes[number].id, address, data) == -1) {
                            log_error(line_copy);
                            printf("?\n");
                        }
                    }
                }
            }
        } else if(strcmp(input, "bt") == 0){
            log_input(line_copy);
            struct user_regs_struct regs;
            if(argNumber > 3 || argNumber == 1){
                log_error(input);
                printf("?\n");
            } else {
                int number2 = 10;
                if(args[2] != NULL) number2 = atoi(args[2]);
                int number = atoi(args[1]);
                int x = 0;

                // Get the current register values
                if (ptrace(PTRACE_GETREGS, processes[number].id, NULL, &regs) == -1) {
                    log_error(input);
                    printf("?\n");
                    x = 1;
                }

                uintptr_t rbp = regs.rbp;
                int frame_count = 0;
                while (rbp != 0x1 && frame_count < number2 && x == 0) {
                    // Read the return address from the stack frame
                    uintptr_t return_address = ptrace(PTRACE_PEEKDATA, processes[number].id, (void*)(rbp + 0x8), NULL);

                    if (return_address == -1 && errno != 0) {
                        log_error(input);
                        printf("?\n");
                        x = 1;
                        break;
                    }
                    if(x == 0){
                        printf("%016lx\t%016lx\n", rbp, return_address);
                        fflush(stdout);
                        // Move to the next stack frame
                        rbp = ptrace(PTRACE_PEEKDATA, processes[number].id, (void*)rbp, NULL);
                        ++frame_count;
                    }
                }
            }
        } else if(strcmp(input, "") == 0){
            log_input(line_copy);
        } else {
            log_input(line_copy);
            log_error(input);
            printf("?\n");
        }
        if(feof(stdin)){
           exitProg();
        }
    }
}

void exitProg(){
    free(line_copy);
    endflag = 1;
    for(int i = 0; i < MAX_CHILDREN; i++){
        if(processes[i].id != 0){
            if(processes[i].state != PSTATE_DEAD && processes[i].state != PSTATE_KILLED) {
                log_state_change(processes[i].id, processes[i].state, PSTATE_KILLED, 0);
                processes[i].state = PSTATE_KILLED;
                processes[i].changeFlag = 1;
            } else {
                processes[i].changeFlag = 0;
            }
        }
    }
    for(int i = 0; i < MAX_CHILDREN; i++){
        if(processes[i].id != 0){
            if(processes[i].state == PSTATE_KILLED){
                printf("%d\t%d\t%c\t", i, processes[i].id, processes[i].traced);
                printf("killed\t\t");
                for(int j = 1; j < processes[i].argnumber; j++){
                    printf("%s ", processes[i].arguments[j]);
                }
                printf("\n");
            }
        }
    }
    for(int i = 0; i < MAX_CHILDREN; i++){
        if(processes[i].id != 0){
            if(processes[i].state != PSTATE_DEAD) {
                kill(processes[i].id, SIGKILL);
                processes[i].state = PSTATE_DEAD;
                usleep(1500);
                checkChildFlag();
            }
            fflush(stdout);
        }
    }
    for(int i = 0; i < MAX_CHILDREN; i++){
        if(processes[i].id != 0 && processes[i].changeFlag == 1){
            printf("%d\t%d\t%c\t", i, processes[i].id, processes[i].traced);
            printf("dead\t0x%d\t", processes[i].exitStatus);
            for(int j = 1; j < processes[i].argnumber; j++){
                printf("%s ", processes[i].arguments[j]);
            }
            printf("\n");
        }
    }
    for(int i = 0; i < MAX_CHILDREN; i++){
        if(processes[i].id != 0){
            for(int j = 1; j < processes[i].argnumber; j++){
                free(processes[i].arguments[j]);
            }
        }
    }
    usleep(1000);
    log_shutdown();
    exit(0);
}

void checkChildFlag(){
    if(childFlag){
        int x = 0;
        for(int i = 0; i < MAX_CHILDREN; i++){
            if(processes[i].id == pidchild){
                x = i;
                break;
            }
        }
        // printf("%d\n", pidchild);
        if (pidchild > 0) {
            if (WIFEXITED(childstatus)) {
                log_state_change(pidchild, PSTATE_RUNNING, PSTATE_DEAD,  WEXITSTATUS(childstatus));
                processes[x].exitStatus = WEXITSTATUS(childstatus);
                processes[x].state = PSTATE_DEAD;
            } else if (WIFSIGNALED(childstatus)) {
                log_state_change(pidchild, PSTATE_KILLED, PSTATE_DEAD, WTERMSIG(childstatus));
                processes[x].exitStatus = childstatus;
                processes[x].state = PSTATE_DEAD;
            } else if (WIFSTOPPED(childstatus)) {
                log_state_change(pidchild, PSTATE_RUNNING, PSTATE_STOPPED, 0);
                processes[x].state = PSTATE_STOPPED;
            } else if (WIFCONTINUED(childstatus)) {
                log_state_change(pidchild, PSTATE_STOPPED, PSTATE_RUNNING, 0);
                processes[x].state = PSTATE_RUNNING;
            }
        }
        if(strcmp(input, "quit") != 0 && endflag == 0){
            //printing of the commands
            for(int i = 0; i < MAX_CHILDREN; i++){
                if(processes[i].id == pidchild){
                    printf("%d\t%d\t%c\t", i, pidchild, processes[i].traced);
                    if(processes[i].state == PSTATE_RUNNING) printf("running\t\t");
                    if(processes[i].state == PSTATE_STOPPED) printf("stopped\t\t");
                    if(processes[i].state == PSTATE_DEAD) printf("dead\t0x%d\t", processes[x].exitStatus);
                    for(int j = 1; j < processes[i].argnumber; j++){
                        printf("%s ", processes[i].arguments[j]);
                    }
                    printf("\n");
                    break;
                }
            }
        }
        childFlag = 0;
    }
}
