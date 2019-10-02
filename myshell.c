#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#define TRUE 1
#define FALSE 0

/**
* Constant and structures
*/

#define CMD_INITIAL_SIZE 16
#define HISTORY_INITIAL_COUNT 16
#define BIN_PATH "/bin/" // Good for now

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

/**
* Function declarations
*/

ShellCtx *start_shell();

Cmd make_cmd();
void destroy_cmd();

CmdToken *make_token();
CmdToken *make_token_after(CmdToken *parent);
CmdToken *tokenize_cmd(ShellCtx *ctx);

char get_next_char(ShellCtx *ctx);
char get_escaped_char(ShellCtx *ctx);
void append_ch(Cmd *cmd, char ch);
void parse_token_quoted(ShellCtx *ctx, char quote, CmdToken *token);
void destroy_token(CmdToken *token);

void print_cmd_safe(Cmd cmd);
void print_history(ShellCtx *ctx);

void change_cwd(ShellCtx *ctx, char *dir);

// Takes in a cmd formatted like this: !x such as [!10], [!0], [!49]
// Returns true when the operation is successful
int replay_command(ShellCtx *ctx, Cmd cmd);

// Checks if the content of a command/token equals to str
// str must be null terminated
int cmd_equals(Cmd cmd, char *str);

// Returns a proper null-terminated string that needs to be freed afterwards
char *get_cmd_string(Cmd cmd);

// Returns true when the command has been handled
int parse_shell_cmd(ShellCtx *ctx, CmdToken *token);

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

CmdToken *tokenize_cmd(ShellCtx *ctx) {
    CmdToken *root = make_token();
    CmdToken *current = root;
    int switch_new_token = FALSE;
    int begin_cmd = TRUE;
    while (TRUE) {
        char ch = get_next_char(ctx);
        // Strip begining spaces
        while (begin_cmd && (strchr(" \t\v\r\f", ch) != NULL)) {
            ch = get_next_char(ctx);
        }
        begin_cmd = FALSE;
        if (ch == EOF) exit(EXIT_SUCCESS);
        if (ch == '\n') break;
        if (ch == '"' || ch == '\'') {
            parse_token_quoted(ctx, ch, current);
            continue;
        }
        if (ch == '>' || ch == '<' || ch == '|') {
            // Ends writing to current token
            current = make_token_after(current);
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
            current = make_token_after(current);
            switch_new_token = FALSE;
        }
        append_ch(&current->token, ch);
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
            ctx->cmd_history.history = realloc(
                                           ctx->cmd_history.history,
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

void destroy_token(CmdToken *token) {
    CmdToken *current = token;
    while (current != NULL) {
        CmdToken *old = current;
        current = current->next;
        destroy_cmd(&old->token);
        free(old);
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
            printf("Invalid command.\n");
        }
        return TRUE;
    }
    if (token->token.length > 0 && token->token.content[0] == '!') {
        if (token->next != NULL || !replay_command(ctx, token->token)) {
            printf("Invalid command.\n");
        }
        return TRUE;
    }
    return FALSE;
}

void change_cwd(ShellCtx *ctx, char *dir) {
    if (chdir(dir)) {
        switch (errno) {
            case ENOENT:
                printf("No such file or directory\n");
                break;
            case ENOTDIR:
                printf("Not a directory\n");
                break;
            default:
                printf("Directory inaccessable\n");
                break;
        }
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

int main() {
    ShellCtx *ctx = start_shell();
    while (TRUE) {
        printf(":%s $ ", ctx->cwd);
        CmdToken *token = tokenize_cmd(ctx);
        CmdToken *current;
        for (current = token; current != NULL; current = current->next) {
            printf("[");
            print_cmd_safe(current->token);
            printf("] ");
        }
        printf("\n");
        parse_shell_cmd(ctx, token);
    }
    return 0;
}
