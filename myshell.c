#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#define TRUE 1
#define FALSE 0

/**
* Constant and structures
*/

#define CMD_INITIAL_SIZE 16
#define HISTORY_INITIAL_COUNT 16
#define PROC_ARGS_INITIAL_COUNT 16

/* A structure to store arbitrary length of a command/token */
typedef struct Cmd {
    char *content;
    int length;
    int max_length;
} Cmd;

/* Stores tokens split from a command */
typedef struct CmdToken {
    struct CmdToken *prev;
    Cmd token;
    struct CmdToken *next;
} CmdToken;

/* Stores command history */
typedef struct CmdHistory {
    Cmd *history;
    int count;
    int max_count;
    Cmd record_buff;
    Cmd replay_buff;
} CmdHistory;

/* Stores everything about the current shell */
typedef struct ShellCtx {
    CmdHistory cmd_history;
    char *cwd;
} ShellCtx;

/* Stores the process being executed */
typedef struct Process {
    struct Process *prev;
    int redir_in, redir_out;
    int pipe_out;
    char *bin;
    char **args;
    int args_count;
    int args_max_count;
    struct Process *next;
} Process;

/**
* Function declarations
*/

ShellCtx *start_shell();

Cmd make_cmd();
void destroy_cmd();

CmdToken *make_token();
CmdToken *make_token_after(CmdToken *parent);
void destroy_token(CmdToken *token);

Process *make_process();
Process *make_process_after(Process *preceding);
void destroy_processes(Process *proc);

char get_next_char(ShellCtx *ctx);
char get_escaped_char(ShellCtx *ctx);
void append_ch(Cmd *cmd, char ch);

void print_cmd_safe(Cmd cmd);
void print_history(ShellCtx *ctx);

void change_cwd(ShellCtx *ctx, char *dir);

// Read and parse user input into tokens
CmdToken *tokenize_cmd(ShellCtx *ctx);

// Parse quoted string into a single token
void parse_token_quoted(ShellCtx *ctx, char quote, CmdToken *token);

// Takes in a cmd formatted like this: !x such as [!10], [!0], [!49]
// Replays the xth command in myhistory
// Returns true when the operation is successful
int replay_command(ShellCtx *ctx, Cmd cmd);

// Checks if the content of a command/token starts with `str`
// `str` must be null terminated
int cmd_starts_with(Cmd cmd, char *str);

// Checks if the content of a command/token equals to `str`
// `str` must be null terminated
int cmd_equals(Cmd cmd, char *str);

// Returns a proper null-terminated string of `cmd` that needs to be freed afterwards
char *get_cmd_string(Cmd cmd);

// Checks for and handles shell commands like cd, !x, myhistory
// Returns true when the command has been handled
int parse_shell_cmd(ShellCtx *ctx, CmdToken *token);

// Returns a list of processes that should be executed
// The returned list of processes must be cleaned up using destroy_processes()
// This function will always return at least a Process that needs to be cleaned up
Process *parse_process_cmd(ShellCtx *ctx, CmdToken *token);

// Executes a list of processes
// The list of processes will be cleaned up automatically
void execute_processes(Process *proc);

// Returns true when the shell is awaiting user input
int awaiting_input(ShellCtx *ctx);

// Returns true when the token contains special shell commands
int is_special_token(CmdToken *token);

ShellCtx *start_shell() {
    ShellCtx *ctx = malloc(sizeof(ShellCtx));
    ctx->cmd_history.history = malloc(sizeof(Cmd)*HISTORY_INITIAL_COUNT);
    ctx->cmd_history.count = 0;
    ctx->cmd_history.max_count = HISTORY_INITIAL_COUNT;
    ctx->cmd_history.record_buff = make_cmd();
    ctx->cmd_history.replay_buff = make_cmd();
    ctx->cwd = get_current_dir_name();
    return ctx;
}

Cmd make_cmd() {
    Cmd cmd;
    cmd.content = malloc(sizeof(char)*CMD_INITIAL_SIZE);
    cmd.length = 0;
    cmd.max_length = CMD_INITIAL_SIZE;
    return cmd;
}

void destroy_cmd(Cmd *cmd) {
    free(cmd->content);
    cmd->content = NULL;
    cmd->length = 0;
    cmd->max_length = 0;
}

CmdToken *make_token() {
    CmdToken *token = malloc(sizeof(CmdToken));
    token->prev = NULL;
    token->token = make_cmd();
    token->next = NULL;
    return token;
}

CmdToken *make_token_after(CmdToken *parent) {
    CmdToken *child = make_token();
    parent->next = child;
    child->prev = parent;
    return child;
}

void destroy_token(CmdToken *token) {
    CmdToken *current = token;
    while (current != NULL) {
        CmdToken *old = current;
        current = current->next;
        destroy_cmd(&old->token);
        free(old);
    }
}

Process *make_process() {
    Process *proc = malloc(sizeof(Process));
    proc->prev = NULL;
    proc->redir_in = -1;
    proc->redir_out = -1;
    proc->pipe_out = -1;
    proc->bin = NULL;
    proc->args = malloc(sizeof(char*)*PROC_ARGS_INITIAL_COUNT);
    proc->args[0] = NULL;
    proc->args[1] = NULL;
    proc->args_count = 1;
    proc->args_max_count = PROC_ARGS_INITIAL_COUNT;
    proc->next = NULL;
    return proc;
}

Process *make_process_after(Process *preceding) {
    Process *proc = make_process();
    preceding->next = proc;
    proc->prev = preceding;
    return proc;
}

void destroy_processes(Process *proc) {
    Process *current = proc;
    while (current != NULL) {
        Process *old = current;
        current = current->next;
        if (old->redir_in != -1 && !close(old->redir_in)) {
            old->redir_in = -1;
        }
        if (old->redir_out != -1 && !close(old->redir_out)) {
            old->redir_out = -1;
        }
        if (old->pipe_out != -1 && !close(old->pipe_out)) {
            old->pipe_out = -1;
        }
        free(old->bin);
        old->bin = NULL;
        int i;
        for(i=0;i<old->args_count;i++) {
            free(old->args[i]);
        }
        old->args_count = 0;
        free(old->args);
        old->args = NULL;
        free(old);
    }
}

CmdToken *tokenize_cmd(ShellCtx *ctx) {
    CmdToken *root = NULL;
    CmdToken *current = NULL;
    int switch_new_token = TRUE;
    while (TRUE) {
        char ch = get_next_char(ctx);
        if (ch == EOF) exit(EXIT_SUCCESS);
        if (ch == '\n') break;
        if (ch == '>' || ch == '<' || ch == '|') {
            // Make a new token
            if (root == NULL) {
                root = make_token();
                current = root;
            } else {
                current = make_token_after(current);
            }
            // Writes a single character to the new token
            append_ch(&current->token, ch);
            switch_new_token = TRUE;
            continue;
        }
        if (strchr(" \t\v\r\f", ch) != NULL) {
            switch_new_token = TRUE;
            continue;
        }
        if (ch == '\\') {
            ch = get_escaped_char(ctx);
        }
        if (switch_new_token) {
            if (root == NULL) {
                root = make_token();
                current = root;
            } else {
                current = make_token_after(current);
            }
            switch_new_token = FALSE;
        }
        if (ch == '"' || ch == '\'') {
            parse_token_quoted(ctx, ch, current);
        } else {
            append_ch(&current->token, ch);
        }
    }
    return root;
}

void parse_token_quoted(ShellCtx *ctx, char quote, CmdToken *token) {
    while (TRUE) {
        char ch = get_next_char(ctx);
        if (ch == quote) return;
        if (ch == '\\') {
            ch = get_escaped_char(ctx);
        }
        append_ch(&token->token, ch);
    }
}

void append_ch(Cmd *cmd, char ch) {
    if (cmd->max_length <= 0) return;
    if (cmd->length >= cmd->max_length) {
        cmd->max_length *= 2;
        cmd->content = realloc(cmd->content, sizeof(char)*cmd->max_length);
    }
    cmd->content[cmd->length++] = ch;
}

char get_next_char(ShellCtx *ctx) {
    Cmd *record_buff = &ctx->cmd_history.record_buff;
    Cmd *replay_buff = &ctx->cmd_history.replay_buff;
    if (replay_buff->length > 0) {
        return replay_buff->content[--replay_buff->length];
    }
    char ch = getchar();
    if (ch != '\n') {
        append_ch(record_buff, ch);
    } else if (record_buff->length > 0) {
        // Adds to history
        if (ctx->cmd_history.count >= ctx->cmd_history.max_count) {
            ctx->cmd_history.max_count *= 2;
            ctx->cmd_history.history = realloc(ctx->cmd_history.history,
                                           sizeof(Cmd)*ctx->cmd_history.max_count
                                       );
        }
        ctx->cmd_history.history[ctx->cmd_history.count++] = *record_buff;
        ctx->cmd_history.record_buff = make_cmd();
    }
    return ch;
}

/* Good enough, lol */
char get_escaped_char(ShellCtx *ctx) {
    char escaped = get_next_char(ctx);
    switch(escaped) {
        case 'n':
            return '\n';
        case 'r':
            return '\r';
        case 't':
            return '\t';
        case 'v':
            return '\v';
        case 'b':
            return '\b';
        default:
            return escaped;
    }
}

char *get_cmd_string(Cmd cmd) {
    char *cmd_str = malloc(sizeof(char)*(cmd.length+1));
    memcpy(cmd_str, cmd.content, cmd.length);
    cmd_str[cmd.length] = '\0';
    return cmd_str;
}

void print_cmd_safe(Cmd cmd) {
    char *cmd_str = get_cmd_string(cmd);
    printf("%s", cmd_str);
    free(cmd_str);
}

void print_history(ShellCtx *ctx) {
    int i;
    for (i=0;i<ctx->cmd_history.count;i++) {
        printf(" %i\t", i);
        print_cmd_safe(ctx->cmd_history.history[i]);
        printf("\n");
    }
}

int cmd_starts_with(Cmd cmd, char *str) {
    int str_len = strlen(str);
    if (cmd.length < str_len) return FALSE;
    if (strncmp(cmd.content, str, str_len)) return FALSE;
    return TRUE;
}

int cmd_equals(Cmd cmd, char *str) {
    if (cmd.length != strlen(str)) return FALSE;
    if (strncmp(cmd.content, str, cmd.length)) return FALSE;
    return TRUE;
}

int parse_shell_cmd(ShellCtx *ctx, CmdToken *token) {
    if (cmd_equals(token->token, "myhistory") && token->next == NULL) {
        print_history(ctx);
        return TRUE;
    }
    if (cmd_equals(token->token, "cd")) {
        if (token->next != NULL) {
            char *cwd = get_cmd_string(token->next->token);
            change_cwd(ctx, cwd);
            free(cwd);
        } else {
            printf("Invalid command\n");
        }
        return TRUE;
    }
    if (cmd_starts_with(token->token, "!")) {
        if (token->next != NULL || !replay_command(ctx, token->token)) {
            printf("Invalid command\n");
        }
        return TRUE;
    }
    return FALSE;
}

void change_cwd(ShellCtx *ctx, char *dir) {
    if (chdir(dir)) {
        perror("cd");
    }
    free(ctx->cwd);
    ctx->cwd = get_current_dir_name();
}

int replay_command(ShellCtx *ctx, Cmd cmd) {
    if (cmd.length < 2) return FALSE;
    char *num_str = malloc(sizeof(char)*(cmd.length));
    memcpy(num_str, cmd.content+1, cmd.length-1);
    num_str[cmd.length-1] = '\0';
    char *endptr;
    int num = strtol(num_str, &endptr, 10);
    ctx->cmd_history.count--; // Removes !x command from history
    if (endptr != num_str && num >= 0 && num < ctx->cmd_history.count) {
        ctx->cmd_history.replay_buff.length = 0;
        append_ch(&ctx->cmd_history.replay_buff, '\n');
        Cmd replayed = ctx->cmd_history.history[num];
        int i;
        for (i=replayed.length-1;i>=0;i--) {
            append_ch(&ctx->cmd_history.replay_buff, replayed.content[i]);
        }
        free(num_str);
        return TRUE;
    } else {
        free(num_str);
        return FALSE;
    }
}

int awaiting_input(ShellCtx *ctx) {
    return ctx->cmd_history.replay_buff.length <= 0;
}

int is_special_token(CmdToken *token) {
    if (token == NULL) return FALSE;
    if (token->token.length <= 0) return FALSE;
    return strchr("!|<>", token->token.content[0]) != NULL;
}

Process *parse_process_cmd(ShellCtx *ctx, CmdToken *token) {
    Process *result = make_process();
    Process *cur_process = result;
    CmdToken *cur_token;
    for (cur_token = token; cur_token != NULL; cur_token = cur_token->next) {
        if (cmd_equals(cur_token->token, "<")) {
            // Prepare for stdin redirection
            cur_token = cur_token->next;
            if (cur_token == NULL || is_special_token(cur_token)) {
                printf("Invalid command\n");
                return result;
            }
            char *path = get_cmd_string(cur_token->token);
            if (cur_process->redir_in != -1) {
                close(cur_process->redir_in);
                cur_process->redir_in = -1;
            }
            cur_process->redir_in = open(path, O_RDONLY);
            if (cur_process->redir_in == -1) {
                perror(path);
                free(path);
                return result;
            }
            free(path);
            continue;
        }
        if (cmd_equals(cur_token->token, ">")) {
            // Prepare for stdout redirection
            int flags = O_CREAT|O_WRONLY;
            cur_token = cur_token->next;
            if (cur_token == NULL) {
                printf("Invalid command\n");
                return result;
            }
            if (cmd_equals(cur_token->token, ">")) {
                flags |= O_APPEND;
                cur_token = cur_token->next;
            } else {
                flags |= O_TRUNC;
            }
            if (cur_token == NULL || is_special_token(cur_token)) {
                printf("Invalid command\n");
                return result;
            }
            char *path = get_cmd_string(cur_token->token);
            if (cur_process->redir_out != -1) {
                close(cur_process->redir_out);
                cur_process->redir_out = -1;
            }
            cur_process->redir_out = open(path, flags, 0664);
            if (cur_process->redir_out == -1) {
                perror(path);
                free(path);
                return result;
            }
            free(path);
            continue;
        }
        if (cmd_equals(cur_token->token, "|")) {
            // Prepare for next process
            // Only pipes output to next process when there's no output redirection
            if (cur_process->redir_out == -1) {
                int pipe_fd[2];
                pipe(pipe_fd);
                cur_process->redir_out = pipe_fd[1];
                cur_process->pipe_out = pipe_fd[0];
            }
            cur_process = make_process_after(cur_process);
            continue;
        }
        if (is_special_token(cur_token)) {
            // Undefined special token
            printf("Invalid command\n");
            return result;
        }
        // Parse bin and args
        if (cur_process->bin == NULL) {
            cur_process->bin = get_cmd_string(cur_token->token);
            cur_process->args[0] = get_cmd_string(cur_token->token);
        } else {
            // Count +1 for the NULL pointer of `cur_process.args`
            if (cur_process->args_count + 1 >= cur_process->args_max_count) {
                cur_process->args_max_count *= 2;
                cur_process->args = realloc(cur_process->args,
                                       sizeof(char*)*cur_process->args_max_count
                                   );
            }
            cur_process->args[cur_process->args_count++] = get_cmd_string(cur_token->token);
            cur_process->args[cur_process->args_count] = NULL;
        }
    }
    return result;
}

void execute_processes(Process *proc) {
    Process *current;
    int child_count = 0;
    for (current = proc; current != NULL; current = current->next) {
        if (current->bin == NULL) {
            // Nothing to run, closing all fds
            if (current->redir_in != -1) {
                close(current->redir_in);
                current->redir_in = -1;
            }
            if (current->redir_out != -1) {
                close(current->redir_out);
                current->redir_out = -1;
            }
            if (current->pipe_out != -1) {
                close(current->pipe_out);
                current->pipe_out = -1;
            }
            if (current->prev != NULL && current->prev->pipe_out != -1) {
                close(current->prev->pipe_out);
                current->prev->pipe_out = -1;
            }
            continue;
        }
        child_count++;
        int pid = fork();
        if (pid == 0) {
            // Redirect stdin of parent to the first child only if appropriate
            if (current == proc && current->redir_in == -1) {
                current->redir_in = STDIN_FILENO;
            }
            // Redirect stdout of parent to the last child only if appropriate
            if (current->next == NULL && current->redir_out == -1) {
                current->redir_out = STDOUT_FILENO;
            }
            // Close all irrelevant fds
            destroy_processes(current->next);
            /* Dups stdin or close it */
            if (current->redir_in != -1) {
                dup2(current->redir_in, STDIN_FILENO);
            }
            if (current->prev != NULL && current->prev->pipe_out != -1) {
                // Close prev pipe_out if the process already has a redir_in
                // Otherwise dup it
                if (current->redir_in != -1) {
                    close(current->prev->pipe_out);
                    current->prev->pipe_out = -1;
                } else {
                    current->redir_in = current->prev->pipe_out;
                    dup2(current->redir_in, STDIN_FILENO);
                }
            }
            // If afterall there's still no stdin redirect, close it
            if (current->redir_in == -1) {
                close(STDIN_FILENO);
            }
            /* Dups stdout or close it */
            if (current->redir_out != -1) {
                dup2(current->redir_out, STDOUT_FILENO);
            } else {
                close(STDOUT_FILENO);
            }
            // Executes binary
            execvp(current->bin, current->args);
            perror(current->bin);
            exit(EXIT_FAILURE);
        } else if (pid > 0) {
            // Close redir_in/redir_out fd
            if (current->redir_in != -1) {
                close(current->redir_in);
                current->redir_in = -1;
            }
            if (current->redir_out != -1) {
                close(current->redir_out);
                current->redir_out = -1;
            }
            // Close prev pipe out
            if (current->prev != NULL && current->prev->pipe_out != -1) {
                close(current->prev->pipe_out);
                current->prev->pipe_out = -1;
            }
        } else {
            perror("fork");
        }
    }
    // Does a final cleanup for strings and args also for the last pipe_out
    destroy_processes(proc);
    // Waits children
    int i;
    for (i=0;i<child_count;i++) {
        wait(NULL);
    }
}

void debug_cmd(CmdToken *token) {
    CmdToken *current;
    for (current = token; current != NULL; current = current->next) {
        printf("[");
        print_cmd_safe(current->token);
        printf("] ");
    }
    printf("\n");
}

void debug_proc(Process *proc) {
    printf("\n===== Execution plan for processes =====\n");
    Process *current;
    int i = 1;
    for (current = proc; current != NULL; current = current->next) {
        printf("Process [%d]:\n", i++);
        printf("bin: %s\nredir_in: %d\nredir_out: %d\npipe_out: %d\n",
            (current->bin != NULL) ? current->bin : "NULL",
            current->redir_in, current->redir_out, current->pipe_out);
        printf("Args: ");
        if (current->args != NULL) {
            printf("\n");
            int j;
            for (j=0;j<current->args_count;j++) {
                printf(" [%d] %s\n", j, current->args[j]);
            }
            printf(" Null terminated? %s\n",
                (current->args[j]==NULL) ? "YES" : "NO (CRITICAL ERROR!!!)");
        } else {
            printf("NULL\n");
        }
        printf("\n");
    }
}

int main() {
    ShellCtx *ctx = start_shell();
    while (TRUE) {
        if (awaiting_input(ctx)) {
            printf(":%s $ ", ctx->cwd);
        }
        CmdToken *token = tokenize_cmd(ctx);
        if (token == NULL) continue;
        if (parse_shell_cmd(ctx, token)) continue;
        execute_processes(parse_process_cmd(ctx, token));
    }
    return 0;
}
