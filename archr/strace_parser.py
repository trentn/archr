import ply.lex as lex
import ply.yacc as yacc

import logging


l = logging.getLogger("archr.strace_parser")

tokens = (
    "SPACE",
    "NUMBER",
    "HEX_NUMBER",
    "RIGHT_PAREN",
    "LEFT_PAREN",
    "COMMA",
    "EQUALS",
    "SYMBOL",
    "ERRNO_S",
    "STRING"
)

def t_SPACE(t):
    r"\s+"
    pass

def t_HEX_NUMBER(t):
    r"0x[0-9a-f]+"
    t.value = int(t.value,16)
    return t

def t_NUMBER(t):
    r"-*\d+"
    t.value = int(t.value)
    return t

t_LEFT_PAREN = r"\("
t_RIGHT_PAREN = r"\)"

def t_COMMA(t):
    r","
    pass

t_EQUALS = r"="

special_symbols = {
    'errno': 'ERRNO_S',
}

def t_SYMBOL(t):
    r"[a-zA-Z][a-zA-Z0-9_|]+"
    t.type = special_symbols.get(t.value, t.type)
    return t


def t_STRING(t):
    r"\".+\""
    #lets strip the quotes
    t.value = t.value[1:-1]
    return t

def t_error(t):
    raise TypeError("Unknown text '%s'" % (t.value,))

lex.lex()



class StraceEntry(object):
    def __init__(self,pid,syscall,error):
        self.pid=pid
        self.syscall=syscall
        self.error=error

    def __repr__(self):
        return "StraceEntry(%s,%s,%s)" % (self.pid, self.syscall, self.error)

class Syscall(object):
    def __init__(self,syscall,args,result):
        self.syscall = syscall
        self.args = args
        self.result = result

    def __eq__(self, other):
        if not isinstance(other,str):
            raise NotImplementedError

        return other == self.syscall

    def __repr__(self):
        return "Syscall(%s, args=%s, result=%s)" % (self.syscall, self.args, self.result)

class Error(object):
    def __init__(self,errno,message):
        self.errno = errno
        self.message = message
    
    def __repr__(self):
        return "ERROR(%s, %s)" % (self.errno, self.message)

def p_strace_line(p):
    """
    strace_line : NUMBER syscall
    strace_line : NUMBER syscall error_message
    """
    p[0] = StraceEntry(p[1], p[2], p[3] if len(p) > 3 else None)

def p_syscall(p):
    """
    syscall : SYMBOL LEFT_PAREN arg_list RIGHT_PAREN result
    syscall : SYMBOL LEFT_PAREN arg_list RIGHT_PAREN
    """
    p[0] = Syscall(p[1], p[3], p[5] if len(p) > 5 else None)

def p_error_message(p):
    """
    error_message : ERRNO_S result LEFT_PAREN arg_list RIGHT_PAREN
    """
    p[0] = Error(p[2],' '.join(p[4]))
    
def p_result(p):
    """
    result : EQUALS NUMBER
    result : EQUALS HEX_NUMBER
    """
    p[0] = p[2]

def p_arg_list(p):
    """
    arg_list : arg_list SYMBOL
    arg_list : arg_list STRING
    arg_list : arg_list NUMBER
    arg_list : arg_list HEX_NUMBER
    arg_list : SYMBOL
    arg_list : STRING
    arg_list : NUMBER
    arg_list : HEX_NUMBER
    """
    if len(p) == 2:
        p[0] = [p[1]]
    else:
        p[0] = p[1]
        p[0].append(p[2])


def p_error(p):
    print("Syntax error at '%s'" % p.value)

yacc.yacc()

def parse(strace_log_lines):
    entries = []
    for line in strace_log_lines:
        entry = yacc.parse(line)
        l.debug(entry)
        entries.append(entry)

    return entries

if __name__ == "__main__":
    import sys
    with open(sys.argv[1], 'r') as log_f:
        entries = parse(log_f.readlines())
    