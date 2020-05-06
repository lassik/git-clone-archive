// Copyright 2020 Lassi Kortela
// SPDX-License-Identifier: ISC

#include <sys/stat.h>
#include <sys/wait.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROGNAME "git2tar"

#define TAR_UID 0
#define TAR_GID 0

struct ent {
    unsigned long unix_file_mode;
    char *git_object_type;
    char *git_object_hash;
    char *file_name;
};

static unsigned int vflags = 2;
static int null_device;

static void fatal(const char *msg)
{
    fprintf(stderr, "%s: %s\n", PROGNAME, msg);
    exit(2);
}

static void fatal_errno(const char *msg)
{
    fprintf(stderr, "%s: %s: %s\n", PROGNAME, msg, strerror(errno));
    exit(2);
}

static void finish(pid_t child)
{
    int status;

    if (waitpid(child, &status, 0) == (pid_t)-1) {
        fatal_errno("cannot wait for git to finish");
    }
    if (!WIFEXITED(status)) {
        fatal("git crashed");
    }
    if (WEXITSTATUS(status) != 0) {
        fatal("git failed");
    }
}

static void run(const char **argv)
{
    pid_t child;

    if ((child = fork()) == (pid_t)-1) {
        fatal_errno("cannot fork");
    }
    if (!child) {
        dup2(null_device, STDOUT_FILENO);
        close(null_device);
        execvp(argv[0], (char **)argv);
        _exit(126);
    }
    finish(child);
}

static void outrun(const char **argv, char **out_buf, size_t *out_len)
{
    pid_t child;
    int outpipe[2];
    char *buf;
    size_t buf_cap, buf_len;
    ssize_t nread;

    if (pipe(outpipe) == -1) {
        fatal_errno("cannot create pipe");
    }
    if ((child = fork()) == (pid_t)-1) {
        fatal_errno("cannot fork");
    }
    if (!child) {
        dup2(outpipe[1], STDOUT_FILENO);
        close(outpipe[0]);
        close(outpipe[1]);
        close(null_device);
        execvp(argv[0], (char **)argv);
        _exit(126);
    }
    close(outpipe[1]);
    buf = 0;
    buf_len = 0;
    buf_cap = 64;
    for (;;) {
        buf_cap *= 2;
        if (!(buf = realloc(buf, buf_cap))) {
            fatal("out of memory");
        }
        nread = read(outpipe[0], buf + buf_len, buf_cap - 1 - buf_len);
        if (nread == (ssize_t)-1) {
            if (errno == EINTR) {
                continue;
            }
            fatal_errno("cannot read from subprocess");
        }
        if (!nread) {
            break;
        }
        buf_len += nread;
    }
    close(outpipe[0]);
    finish(child);
    *out_buf = buf;
    *out_len = buf_len;
}

static char *outrun0(const char **argv)
{
    char *buf;
    size_t len;

    outrun(argv, &buf, &len);
    if (memchr(buf, 0, len)) {
        fatal("null byte in git output");
    }
    buf[len] = 0;
    return buf;
}

static char *chomp(char *str)
{
    char *limit = strchr(str, 0);

    if (limit > str) {
        if (limit[-1] == '\n') {
            limit[-1] = 0;
        }
    }
    return str;
}

static void git_clone(const char *url, const char *template)
{
    const char *git_argv[] = { "git", "clone", "--bare", "--depth", "1", "--",
        url, template, 0 };

    run(git_argv);
}

static void git_show(
    const char *git_ref, char **out_contents, size_t *out_filesize)
{
    const char *git_argv[] = { "git", "show", git_ref, 0 };

    outrun(git_argv, out_contents, out_filesize);
}

static char *git_rev_parse(const char *git_ref)
{
    const char *git_argv[] = { "git", "rev-parse", git_ref, 0 };

    return chomp(outrun0(git_argv));
}

static char *git_ls_tree(const char *git_ref)
{
    const char *git_argv[] = { "git", "ls-tree", git_ref, 0 };

    return outrun0(git_argv);
}

static char *scan_until(char *str, char **out_span, int sentinel)
{
    char *limit;
    char *span;
    size_t len;

    if (!(limit = strchr(str, sentinel))) {
        fatal("cannot parse");
    }
    len = limit - str;
    if (!(span = calloc(1, len + 1))) {
        fatal("out of memory");
    }
    memcpy(span, str, len);
    span[len] = 0;
    *out_span = span;
    return limit + 1;
}

static unsigned long parse_unix_file_mode(const char *string)
{
    unsigned long bits;

    sscanf(string, "%lo", &bits);
    return bits;
}

static char *parse_ls_tree_entry(char *tree, struct ent **out_ent)
{
    struct ent *ent;
    char *unix_file_mode;

    *out_ent = 0;
    if (!*tree) {
        return 0;
    }
    if (!(ent = calloc(1, sizeof(*ent)))) {
        fatal("out of memory");
    }
    tree = scan_until(tree, &unix_file_mode, ' ');
    ent->unix_file_mode = parse_unix_file_mode(unix_file_mode);
    free(unix_file_mode);
    tree = scan_until(tree, &ent->git_object_type, ' ');
    tree = scan_until(tree, &ent->git_object_hash, '\t');
    tree = scan_until(tree, &ent->file_name, '\n');
    *out_ent = ent;
    return tree;
}

static void write_to_stdout(void *buf, size_t len)
{
    if (write(STDOUT_FILENO, buf, len) != (ssize_t)len) {
        fatal("cannot write to stdout");
    }
}

static char path[4096];

static void path_truncate(char *limit)
{
    memset(limit, 0, sizeof(path) - (limit - path));
}

static char *path_append(const char *name)
{
    char *pivot;
    char *add;
    int room;

    pivot = add = strchr(path, 0);
    if (add > path) {
        *add++ = '/';
    }
    room = sizeof(path) - (add - path);
    if (snprintf(add, room, "%s", name) >= room) {
        fatal("pathname too long");
    }
    return pivot;
}

static unsigned long sum_bytes(unsigned char *bytes, size_t nbyte)
{
    unsigned long sum = 0;

    for (; nbyte; nbyte--) {
        sum += *bytes++;
    }
    return sum;
}

static char null_bytes[512];
static char tar_header[512];
static char *tar;

static void tar_string(size_t width, const char *value)
{
    size_t len;

    len = strlen(value);
    if (len >= width) {
        fatal("tar limit exceeded");
    }
    memcpy(tar, value, len);
    memset(tar + len, 0, width - len);
    tar += width;
}

static void tar_octal(size_t width, unsigned long value)
{
    size_t ndigit, nzero;
    char digits[width];

    if ((ndigit = snprintf(digits, sizeof(digits), "%lo", value)) >= width) {
        fatal("tar limit exceeded");
    }
    for (nzero = width - 1 - ndigit; nzero; nzero--) {
        *tar++ = '0';
    }
    memcpy(tar, digits, ndigit);
    tar += ndigit;
    *tar++ = 0;
}

static void generate_tar_blob(struct ent *ent)
{
    char *blob;
    char *checksum;
    char *pivot;
    size_t blobsize, i;

    git_show(ent->git_object_hash, &blob, &blobsize);
    memset(tar_header, 0, 512);
    tar = tar_header;
    pivot = path_append(ent->file_name);
    tar_string(100, path);
    path_truncate(pivot);
    tar_octal(8, ent->unix_file_mode);
    tar_octal(8, TAR_UID);
    tar_octal(8, TAR_GID);
    tar_octal(12, blobsize);
    tar_octal(12, 0); // mtime
    checksum = tar;
    for (i = 0; i < 8; i++) {
        *tar++ = ' ';
    }
    *tar++ = '0';
    tar_string(100, "");
    tar_string(8, "ustar  ");
    tar_string(32, "root");
    tar_string(32, "root");
    tar_string(183, "");
    tar = checksum;
    tar_octal(7, sum_bytes((unsigned char *)tar_header, 512) % 01000000UL);
    write_to_stdout(tar_header, 512);
    write_to_stdout(blob, blobsize);
    write_to_stdout(null_bytes, 512 - (blobsize % 512));
}

static void generate_tar_tree(const char *hash)
{
    struct ent *ent;
    char *tree;
    char *pivot;

    tree = git_ls_tree(hash);
    while ((tree = parse_ls_tree_entry(tree, &ent))) {
        if (!strcmp(ent->git_object_type, "blob")) {
            generate_tar_blob(ent);
        } else if (!strcmp(ent->git_object_type, "tree")) {
            pivot = path_append(ent->file_name);
            generate_tar_tree(ent->git_object_hash);
            path_truncate(pivot);
        } else {
            fprintf(stderr, "warning: skipping %s\n", ent->git_object_type);
        }
    }
    free(tree);
}

static void generate_tar_file(void)
{
    char *hash;

    hash = git_rev_parse("HEAD");
    generate_tar_tree(hash);
    free(hash);
    write_to_stdout(null_bytes, 512);
    write_to_stdout(null_bytes, 512);
}

static char *get_tmpdir(void)
{
    const char *const_string;
    char *string;
    char *limit;

    if (!(const_string = getenv("TMPDIR"))) {
        const_string = "/tmp";
    }
    if (!(string = strdup(const_string))) {
        fatal("out of memory");
    }
    for (limit = strchr(string, 0); limit > string; limit--) {
        if (limit[-1] != '/') {
            break;
        }
    }
    *limit = 0;
    return string;
}

static void delete_temp_dir(void);

static void delete_temp_ent(void)
{
    static struct stat st;

    if (lstat(path, &st) == -1) {
        fatal_errno("cannot get info for temp file");
    }
    if (S_ISDIR(st.st_mode)) {
        delete_temp_dir();
        if (vflags >= 2) {
            fprintf(stderr, "rmdir %s\n", path);
        }
        if (rmdir(path) == -1) {
            fatal_errno("cannot delete temp directory");
        }
    } else {
        if (vflags >= 2) {
            fprintf(stderr, "unlink %s\n", path);
        }
        if (unlink(path) == -1) {
            fatal_errno("cannot delete temp file");
        }
    }
}

static void delete_temp_dir(void)
{
    DIR *dir;
    struct dirent *d;
    char *name;
    char *pivot;

    if (!(dir = opendir(path))) {
        fatal_errno("cannot open directory");
    }
    for (;;) {
        errno = 0;
        if (!(d = readdir(dir))) {
            break;
        }
        name = d->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) {
            continue;
        }
        pivot = path_append(name);
        delete_temp_ent();
        path_truncate(pivot);
    }
    if (errno) {
        fatal_errno("cannot list directory");
    }
    if (closedir(dir) == -1) {
        fatal_errno("cannot close directory");
    }
}

static void delete_temp_files(const char *template)
{
    path_truncate(path);
    path_append(template);
    delete_temp_ent();
}

int main(int argc, char **argv)
{
    char template[] = PROGNAME "-XXXXXXXX";
    char *tmpdir;
    const char *url;
    int parentdir;

    if (argc != 2) {
        fatal("usage");
    }
    url = argv[1];
    if (isatty(STDOUT_FILENO)) {
        fatal("standard output is a terminal");
    }
    umask(0077);
    if ((null_device = open("/dev/null", O_RDWR)) == -1) {
        fatal("cannot open /dev/null");
    }
    tmpdir = get_tmpdir();
    if (chdir(tmpdir) == -1) {
        fatal_errno("cannot change directory");
    }
    if (!mkdtemp(template)) {
        fatal_errno("cannot create temporary directory");
    }
    if (vflags >= 1) {
        fprintf(stderr, "%s: %s/%s\n", PROGNAME, tmpdir, template);
    }
    git_clone(url, template);
    if ((parentdir = open(".", O_RDONLY | O_DIRECTORY)) == -1) {
        fatal_errno("cannot open directory");
    }
    if (chdir(template) == -1) {
        fatal_errno("cannot change directory");
    }
    generate_tar_file();
    if (fchdir(parentdir) == -1) {
        fatal_errno("cannot change directory");
    }
    delete_temp_files(template);
    return 0;
}
