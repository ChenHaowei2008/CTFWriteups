#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

enum Type {
	NUMBER,
	STRING
};

typedef struct Variable {
	union {
		long num;
		char* buf;
	} val;
	size_t size;
	enum Type type;
	char* name;
} Variable;

Variable *variables[0x1000];
char *strings[0x1000];

void print_var(Variable* value) {
	switch (value->type) {
		case NUMBER: printf("%ld\n", value->val.num); break;
		case STRING: printf("%s\n", value->val.buf); break;
		default: _exit(1);
	}
}

uint64_t hash_str(const char *s) {
	uint64_t hash = 0xcbf29ce484222325ULL;
	while (*s) {
		hash ^= (unsigned char)*s++;
		hash *= 0x100000001b3ULL;
	}
	return hash;
}

Variable *new_string_var(const char *s) {
	Variable *v = malloc(sizeof(Variable));
	if (!v) _exit(1);

	v->type = STRING;
	v->name = NULL;

	size_t idx = (size_t)hash_str(s) % 0xfff;
	if (strings[idx]) {
		v->val.buf = strings[idx]; // string interning!
	} else {
		v->val.buf = strdup(s);
		strings[idx] = v->val.buf;
	}
	if (!v->val.buf) _exit(1);
	v->size = strlen(v->val.buf);

	return v;
}

Variable *new_number_var(long n) {
	Variable *v = malloc(sizeof(Variable));
	if (!v) _exit(1);

	v->type = NUMBER;
	v->name = NULL;
	v->val.num = n;
	v->size = 0;

	return v;
}

void free_var(Variable *var) {
	if (var->type == STRING) free(var->val.buf);
	free(var->name);
	free(var);
}

void set_var(const char* name, const char* p) {
	char *strval;
	long longval = strtol(p+1, &strval, 10);
	Variable *var;

	size_t idx = (size_t)hash_str(name) % 0xfff;

	if (variables[idx]) {
		free_var(variables[idx]);
		variables[idx] = NULL;
	}
	
	if (*strval) {
		var = new_string_var(p+1);
		var->name = strdup(name);
	} else {
		var = new_number_var(longval);
		var->name = strdup(name);
	}
	variables[idx] = var;
}

void modify_var(const char* name, const char* p) {
	char *strval;
	long longval = strtol(p+1, &strval, 10);
	size_t idx = (size_t)hash_str(name) % 0xfff;
	size_t len;
	Variable *var;

	if (!(variables[idx])) return;
	var = variables[idx];

	if (*strval) {
		size_t len = strlen(p+1);
		memcpy(var->val.buf, p+1, (len > var->size) ? var->size : len);
	} else {
		var->val.num = longval;
	}
}

void hint(const char* name) {
	char *p = strchr(name, ')');
	*p = 0;

	Variable *var;
	size_t idx = (size_t)hash_str(name) % 0xfff;
	if (!(variables[idx])) return;
	var = variables[idx];

	printf("%s: %ld\n", name, ((long)var->val.num >> 12) & 0xf);
}

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);

	char cmd[4096];
	char *p;
	int hints = 0;
	// printf("[DEBUG] variables = %p\n", &variables);
	while (1) {
		puts("> ");
		fgets(cmd, sizeof(cmd), stdin);
		
		if (strchr(cmd, '\n'))
			cmd[strcspn(cmd, "\n")] = '\0';
		
		if (cmd[0] == '$') {
			p = strchr(cmd, '*');
			if (p) {
				*p = 0;
				p += 1;
				if (*p == '=') {
					*p = 0;
					modify_var(cmd+1, p);
				} 
			}
			p = strchr(cmd, '=');
			if (p) {
				*p = 0;
				set_var(cmd+1, p);
			}
		}

		if (!strncmp(cmd, "hint(", 5)) {
			if (hints > 0) continue;	
			p = strchr(cmd, '(');
			hint(p+1);
		}
	}
}
