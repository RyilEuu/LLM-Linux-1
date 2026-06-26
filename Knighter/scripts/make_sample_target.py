from __future__ import annotations

import json
from pathlib import Path


def _write_with_line(target: Path, total_lines: int, anchor_line: int, anchor_code: str):
    lines = []
    for i in range(1, total_lines + 1):
        if i == anchor_line:
            lines.append(anchor_code.rstrip("\n"))
        else:
            lines.append("")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    """
    Create a small C code tree that matches `final_report.json` paths/lines,
    so `enrich_code_context` can be validated without external repos.
    """
    root = Path(r"c:\Users\11452\Desktop\软件保障\code\sample_target")
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)

    # Map: file -> (total_lines, anchor_line, code)
    spec = {
        "net.c": (120, 45, "int connect_socket(struct socket *s){ int port = s->port; if(!s) return -1; return port; }"),
        "io.c": (80, 12, "void copy_msg(const char *msg){ char buf[64]; strcpy(buf, msg); }"),
        "mem.c": (140, 88, "int f(int fail){ char *ptr = malloc(16); if(fail) return -1; free(ptr); return 0; }"),
        "thread.c": (90, 30, "void g(pthread_mutex_t *m){ pthread_mutex_unlock(m); pthread_mutex_unlock(m); }"),
        "file.c": (120, 55, "int h(){ int *p = malloc(sizeof(int)); free(p); return *p; }"),
        "auth.c": (180, 102, "void *alloc(int n){ return malloc(n * (int)sizeof(int)); }"),
        "db.c": (60, 22, "int q(){ int status; if(status) return 1; return 0; }"),
        "sys.c": (120, 70, "int div0(int d){ return 100 / d; }"),
        "web.c": (80, 15, "const char *pwd = \"hardcoded_password\";"),
        "util.c": (120, 41, "int arr[8]; int get(int i){ return arr[i]; }"),
        "data.c": (50, 9, "int r(){ return rand(); }"),
        "proc.c": (120, 66, "void lock_order(){ /* false deadlock warning example */ }"),
        "log.c": (90, 33, "void vlog(char *s){ printf(s); }"),
        "api.c": (120, 80, "void readin(){ char buf[16]; gets(buf); }"),
        "app.c": (80, 12, "int leak(){ FILE *f=fopen(\"a\",\"r\"); if(!f) return -1; return 0; }"),
        "crypto.c": (140, 99, "void md5sum(){ /* MD5 used as checksum */ }"),
        "exec.c": (80, 45, "void run(char *cmd){ system(cmd); }"),
        "user.c": (70, 21, "void ptrarith(){ const char *s=\"abc\"; const char *p=s+10; (void)p; }"),
        "conf.c": (40, 5, "int g_var;"),
        "main.c": (240, 200, "void d(){ void *p=malloc(8); free(p); free(p); }"),
    }

    for fname, (total, anchor, code) in spec.items():
        _write_with_line(src / fname, total, anchor, code)

    (root / "README.txt").write_text(
        "This is a generated sample target for code_context enrichment.\n",
        encoding="utf-8",
    )

    # write a helper manifest for debugging
    (root / "manifest.json").write_text(
        json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    main()

